# SMB Share Manager

一个高效的 Go 语言 SMB 共享文件操作库，支持自动超时回收和连接管理。

## 特性

- ✅ **自动连接管理** - 自动建立和维持 SMB 连接
- ✅ **超时自动回收** - 可配置的超时时间，自动清理闲置连接
- ✅ **线程安全** - 所有操作都是线程安全的
- ✅ **多种上传方式** - 支持文件、字节数据和流式上传
- ✅ **错误处理** - 完善的错误处理机制
- ✅ **自动重连** - 挂载点自动切换和重连
- ✅ **资源管理** - 自动资源清理和内存管理

## 安装

```bash
go get github.com/kikiThinking/Share
```

## 快速开始

### 基本用法

```go
package main

import (
	"fmt"
	"log"
	"time"
	
	"github/kikiThinking/Share"
)

func main() {
	// 创建配置
	config := share.Config{
		Username: "admin",
		Password: "password",
		Mount:    "shared",
		ServerIP: "192.168.1.100",
		Timeout:  30 * time.Minute,
	}

	// 创建共享管理器
	sm, err := share.NewShareManager(config)
	if err != nil {
		log.Fatal(err)
	}
	defer sm.Close()

	// 下载文件
	downloadList := []share.FileTransferContext{
		{
			Source:      "\\shared\\docs\\file1.pdf",
			Destination: "local_file1.pdf",
		},
	}

	if err := sm.Download(downloadList); err != nil {
		log.Printf("Download error: %v", err)
	}
}
```

### 文件操作示例

```go
// 上传多个文件
uploadList := []share.FileTransferContext{
	{
		Source:      "local1.txt",
		Destination: "\\shared\\uploads\\file1.txt",
	},
	{
		Source:      "local2.txt", 
		Destination: "\\shared\\uploads\\file2.txt",
	},
}

err := sm.Upload(uploadList)

// 上传字节数据
byteData := []share.FileCreateContext{
	{
		Data:        []byte("Hello SMB!"),
		Destination: "\\shared\\data\\greeting.txt",
	},
}

err = sm.UploadBytes(byteData)

// 列出目录内容
files, err := sm.ListDirectory("\\shared\\docs")
if err == nil {
	for _, file := range files {
		fmt.Printf("%s (Size: %d)\n", file.Name(), file.Size())
	}
}
```

### 流式上传大文件

```go
file, err := os.Open("large_video.mp4")
if err != nil {
	log.Fatal(err)
}
defer file.Close()

err = sm.UploadStream(file, "\\shared\\videos\\large_video.mp4")
```

## API 参考

### Config 配置

| 字段 | 类型 | 说明 |
|------|------|------|
| Username | string | SMB 用户名 |
| Password | string | SMB 密码 |
| Mount | string | 共享名称 |
| ServerIP | string | 服务器IP地址 |
| Timeout | time.Duration | 超时时间，0为不超时 |

### 主要方法

#### NewShareManager(config Config) (*ShareManager, error)
创建新的共享管理器实例。

#### Download(fileList []FileTransferContext) error
下载文件列表。

#### Upload(fileList []FileTransferContext) error
上传文件列表。

#### UploadBytes(fileList []FileCreateContext) error
上传字节数据到文件。

#### UploadStream(source io.Reader, destination string) error
流式上传大文件。

#### ListDirectory(path string) ([]os.FileInfo, error)
列出目录内容。

#### GetFileInfo(path string) (os.FileInfo, error)
获取文件信息。

#### IsDirectory(path string) (bool, error)
检查路径是否为目录。

#### Close() error
关闭连接并清理资源。

#### IsActive() bool
检查管理器是否活跃。

#### ResetTimeout()
重置超时计时器。

## 超时管理

共享管理器支持自动超时回收：

```go
// 30分钟无活动自动关闭
config := share.Config{
    Timeout: 30 * time.Minute,
}

// 手动重置超时计时器
sm.ResetTimeout()

// 检查连接状态
if sm.IsActive() {
    // 执行操作
}
```

## 错误处理

所有方法都返回详细的错误信息：

```go
if err := sm.Download(files); err != nil {
    if strings.Contains(err.Error(), "not active") {
        // 连接已关闭
        sm, _ = share.NewShareManager(config)
    } else {
        log.Printf("Operation failed: %v", err)
    }
}
```

## 最佳实践

1. **使用 defer 关闭连接**
   ```go
   sm, err := share.NewShareManager(config)
   if err != nil {
       return err
   }
   defer sm.Close()
   ```

2. **批量操作文件**
   ```go
   // 一次性处理多个文件，减少连接开销
   files := []share.FileTransferContext{...}
   err := sm.Upload(files)
   ```

3. **大文件使用流式上传**
   ```go
   // 避免内存溢出
   err := sm.UploadStream(reader, destination)
   ```

4. **定期检查连接状态**
   ```go
   if !sm.IsActive() {
       // 重新连接
   }
   ```