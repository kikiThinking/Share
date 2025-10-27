/*
*
@author: kiki
@since: 2024/7/20
@desc: SMB 共享文件操作模块
*/
package share

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hirochachacha/go-smb2"
)

// ShareManager SMB 共享管理器
type ShareManager struct {
	client struct {
		share   *smb2.Share
		session *smb2.Session
	}
	username   string
	password   string
	mount      string
	serverIP   string
	timeout    time.Duration
	lastActive time.Time
	mu         sync.RWMutex
	isActive   bool
	done       chan struct{}
}

// FileTransferContext 文件传输上下文
type FileTransferContext struct {
	Source      string
	Destination string
}

// FileCreateContext 文件创建上下文
type FileCreateContext struct {
	Data        []byte
	Destination string
}

// Config 配置结构
type Config struct {
	Username string
	Password string
	Mount    string
	ServerIP string
	Timeout  time.Duration // 超时时间，0表示不超时
}

// NewShareManager 创建新的共享管理器
func NewShareManager(config Config) (*ShareManager, error) {
	sm := &ShareManager{
		username:   config.Username,
		password:   config.Password,
		mount:      config.Mount,
		serverIP:   config.ServerIP,
		timeout:    config.Timeout,
		isActive:   true,
		lastActive: time.Now(),
		done:       make(chan struct{}),
	}

	if err := sm.connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to SMB server: %w", err)
	}

	// 启动超时监控
	if config.Timeout > 0 {
		go sm.monitorTimeout()
	}

	return sm, nil
}

// connect 连接到 SMB 服务器
func (sm *ShareManager) connect() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:445", sm.serverIP))
	if err != nil {
		return fmt.Errorf("failed to dial server: %w", err)
	}

	dialer := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     sm.username,
			Password: sm.password,
		},
	}

	session, err := dialer.Dial(conn)
	if err != nil {
		return fmt.Errorf("failed to establish SMB session: %w", err)
	}

	share, err := session.Mount(sm.mount)
	if err != nil {
		err := session.Logoff()
		if err != nil {
			return err
		}

		return fmt.Errorf("failed to mount share: %w", err)
	}

	sm.client.session = session
	sm.client.share = share
	sm.lastActive = time.Now()

	return nil
}

// monitorTimeout 监控超时
func (sm *ShareManager) monitorTimeout() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-sm.done:
			return
		case <-ticker.C:
			sm.mu.RLock()
			idleTime := time.Since(sm.lastActive)
			sm.mu.RUnlock()

			if idleTime > sm.timeout {
				sm.cleanup()
				return
			}
		}
	}
}

// updateActivity 更新活动时间
func (sm *ShareManager) updateActivity() {
	sm.mu.Lock()
	sm.lastActive = time.Now()
	sm.mu.Unlock()
}

// cleanup 清理资源
func (sm *ShareManager) cleanup() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.isActive {
		sm.isActive = false
		close(sm.done)

		if sm.client.share != nil {
			err := sm.client.share.Umount()
			if err != nil {
				fmt.Printf("failed to umount share: %v\n", err)
				return
			}
		}
		if sm.client.session != nil {
			err := sm.client.session.Logoff()
			if err != nil {
				fmt.Printf("failed to umount share: %v\n", err)
				return
			}
		}
	}
}

// Download 下载文件
func (sm *ShareManager) Download(fileList []FileTransferContext) error {
	if len(fileList) == 0 {
		return fmt.Errorf("file list is empty")
	}

	sm.updateActivity()
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if !sm.isActive {
		return fmt.Errorf("share manager is not active")
	}

	var errors []string
	for _, file := range fileList {
		if err := sm.downloadSingleFile(file); err != nil {
			errors = append(errors, fmt.Sprintf("file %s: %v", file.Source, err))
			continue
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("download completed with errors: %s", strings.Join(errors, "; "))
	}

	return nil
}

// downloadSingleFile 下载单个文件
func (sm *ShareManager) downloadSingleFile(file FileTransferContext) error {
	fmt.Printf("Downloading: %s -> %s\n", file.Source, file.Destination)

	remotePath, err := sm.normalizePath(file.Source)
	if err != nil {
		return fmt.Errorf("normalize path failed: %w", err)
	}

	// 打开远程文件
	srcFile, err := sm.client.share.Open(remotePath)
	if err != nil {
		return fmt.Errorf("open remote file failed: %w", err)
	}
	defer srcFile.Close()

	// 确保目标目录存在
	if err := os.MkdirAll(filepath.Dir(file.Destination), 0755); err != nil {
		return fmt.Errorf("create local directory failed: %w", err)
	}

	// 创建本地文件
	dstFile, err := os.Create(file.Destination)
	if err != nil {
		return fmt.Errorf("create local file failed: %w", err)
	}
	defer dstFile.Close()

	// 复制文件内容
	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return fmt.Errorf("copy file content failed: %w", err)
	}

	// 获取远程文件信息并设置本地文件时间
	if fileInfo, err := sm.client.share.Stat(remotePath); err == nil {
		_ = os.Chtimes(file.Destination, fileInfo.ModTime(), fileInfo.ModTime())
	}

	fmt.Printf("Download completed: %s\n", file.Destination)
	return nil
}

// Upload 上传文件
func (sm *ShareManager) Upload(fileList []FileTransferContext) error {
	if len(fileList) == 0 {
		return fmt.Errorf("file list is empty")
	}

	sm.updateActivity()
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if !sm.isActive {
		return fmt.Errorf("share manager is not active")
	}

	var errors []string
	for _, file := range fileList {
		if err := sm.uploadSingleFile(file); err != nil {
			errors = append(errors, fmt.Sprintf("file %s: %v", file.Source, err))
			continue
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("upload completed with errors: %s", strings.Join(errors, "; "))
	}

	return nil
}

// uploadSingleFile 上传单个文件
func (sm *ShareManager) uploadSingleFile(file FileTransferContext) error {
	fmt.Printf("Uploading: %s -> %s\n", file.Source, file.Destination)

	remotePath, err := sm.normalizePath(file.Destination)
	if err != nil {
		return fmt.Errorf("normalize path failed: %w", err)
	}

	// 确保远程目录存在
	if err := sm.createRemoteDirectory(filepath.Dir(remotePath)); err != nil {
		return fmt.Errorf("create remote directory failed: %w", err)
	}

	// 读取本地文件内容
	content, err := os.ReadFile(file.Source)
	if err != nil {
		return fmt.Errorf("read local file failed: %w", err)
	}

	// 创建远程文件
	remoteFile, err := sm.client.share.Create(remotePath)
	if err != nil {
		return fmt.Errorf("create remote file failed: %w", err)
	}
	defer remoteFile.Close()

	// 写入内容
	if _, err := remoteFile.Write(content); err != nil {
		return fmt.Errorf("write to remote file failed: %w", err)
	}

	fmt.Printf("Upload completed: %s\n", file.Destination)
	return nil
}

// UploadBytes 上传字节数据
func (sm *ShareManager) UploadBytes(fileList []FileCreateContext) error {
	if len(fileList) == 0 {
		return fmt.Errorf("file list is empty")
	}

	sm.updateActivity()
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if !sm.isActive {
		return fmt.Errorf("share manager is not active")
	}

	var errors []string
	for _, file := range fileList {
		if err := sm.uploadBytes(file); err != nil {
			errors = append(errors, fmt.Sprintf("file %s: %v", file.Destination, err))
			continue
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("upload bytes completed with errors: %s", strings.Join(errors, "; "))
	}

	return nil
}

// uploadBytes 上传字节数据
func (sm *ShareManager) uploadBytes(file FileCreateContext) error {
	fmt.Printf("Uploading bytes to: %s\n", file.Destination)

	remotePath, err := sm.normalizePath(file.Destination)
	if err != nil {
		return fmt.Errorf("normalize path failed: %w", err)
	}

	// 确保远程目录存在
	if err := sm.createRemoteDirectory(filepath.Dir(remotePath)); err != nil {
		return fmt.Errorf("create remote directory failed: %w", err)
	}

	// 创建远程文件
	remoteFile, err := sm.client.share.Create(remotePath)
	if err != nil {
		return fmt.Errorf("create remote file failed: %w", err)
	}
	defer remoteFile.Close()

	// 写入字节数据
	if _, err := remoteFile.Write(file.Data); err != nil {
		return fmt.Errorf("write bytes to remote file failed: %w", err)
	}

	fmt.Printf("Upload bytes completed: %s\n", file.Destination)
	return nil
}

// UploadStream 使用流式上传（适合大文件）
func (sm *ShareManager) UploadStream(source io.Reader, destination string) error {
	sm.updateActivity()
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if !sm.isActive {
		return fmt.Errorf("share manager is not active")
	}

	remotePath, err := sm.normalizePath(destination)
	if err != nil {
		return fmt.Errorf("normalize path failed: %w", err)
	}

	// 确保远程目录存在
	if err := sm.createRemoteDirectory(filepath.Dir(remotePath)); err != nil {
		return fmt.Errorf("create remote directory failed: %w", err)
	}

	// 创建远程文件
	remoteFile, err := sm.client.share.Create(remotePath)
	if err != nil {
		return fmt.Errorf("create remote file failed: %w", err)
	}
	defer remoteFile.Close()

	// 流式复制
	if _, err := io.Copy(remoteFile, source); err != nil {
		return fmt.Errorf("stream upload failed: %w", err)
	}

	return nil
}

// ListDirectory 列出目录内容
func (sm *ShareManager) ListDirectory(path string) ([]os.FileInfo, error) {
	sm.updateActivity()
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if !sm.isActive {
		return nil, fmt.Errorf("share manager is not active")
	}

	normalizedPath, err := sm.normalizePath(path)
	if err != nil {
		return nil, fmt.Errorf("normalize path failed: %w", err)
	}

	return sm.client.share.ReadDir(normalizedPath)
}

// GetFileInfo 获取文件信息
func (sm *ShareManager) GetFileInfo(path string) (os.FileInfo, error) {
	sm.updateActivity()
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if !sm.isActive {
		return nil, fmt.Errorf("share manager is not active")
	}

	normalizedPath, err := sm.normalizePath(path)
	if err != nil {
		return nil, fmt.Errorf("normalize path failed: %w", err)
	}

	return sm.client.share.Stat(normalizedPath)
}

// IsDirectory 检查是否为目录
func (sm *ShareManager) IsDirectory(path string) (bool, error) {
	sm.updateActivity()
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if !sm.isActive {
		return false, fmt.Errorf("share manager is not active")
	}

	normalizedPath, err := sm.normalizePath(path)
	if err != nil {
		return false, fmt.Errorf("normalize path failed: %w", err)
	}

	fileInfo, err := sm.client.share.Stat(normalizedPath)
	if err != nil {
		return false, fmt.Errorf("get file info failed: %w", err)
	}

	return fileInfo.IsDir(), nil
}

// normalizePath 规范化路径并自动切换挂载点
func (sm *ShareManager) normalizePath(path string) (string, error) {
	// 清理路径开头的斜杠
	path = strings.TrimPrefix(path, `\`)
	path = strings.TrimPrefix(path, `/`)

	// 分割路径获取挂载点和相对路径
	parts := strings.Split(strings.NewReplacer(`\`, "/", `/`, "/").Replace(path), "/")
	if len(parts) == 0 {
		return "", fmt.Errorf("invalid path: %s", path)
	}

	shareMount := parts[0]
	relativePath := strings.Join(parts[1:], `\`)

	// 如果挂载点不同，切换挂载点
	if strings.ToUpper(shareMount) != strings.ToUpper(sm.mount) {
		fmt.Printf("Switching mount from %s to %s\n", sm.mount, shareMount)

		newShare, err := sm.client.session.Mount(shareMount)
		if err != nil {
			return "", fmt.Errorf("switch mount failed: %w", err)
		}

		sm.client.share = newShare
		sm.mount = shareMount
	}

	return relativePath, nil
}

// createRemoteDirectory 创建远程目录
func (sm *ShareManager) createRemoteDirectory(path string) error {
	if _, err := sm.client.share.Stat(path); os.IsNotExist(err) {
		if err := sm.client.share.MkdirAll(path, 0755); err != nil {
			return fmt.Errorf("create directory failed: %w", err)
		}
	}
	return nil
}

// Close 关闭连接
func (sm *ShareManager) Close() error {
	sm.cleanup()
	return nil
}

// IsActive 检查管理器是否活跃
func (sm *ShareManager) IsActive() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.isActive
}

// ResetTimeout 重置超时时间
func (sm *ShareManager) ResetTimeout() {
	sm.updateActivity()
}
