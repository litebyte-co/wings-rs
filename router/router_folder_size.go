package router

import (
    "github.com/gin-gonic/gin"
    "github.com/pterodactyl/wings/config"
    "github.com/pterodactyl/wings/router/middleware"
    "net/http"
    "os"
    "path/filepath"
)

type SizeResponse struct {
    Size int64 `json:"size"`
}

func getFolderSize(c *gin.Context) {
    s := middleware.ExtractServer(c)

    var data struct {
        Path string `json:"path"`
    }

    if err := c.BindJSON(&data); err != nil {
        // log.Printf("Failed to bind JSON: %v", err)
        c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Invalid parameters"})
        return
    }

    basePath := config.Get().System.Data
    serverUUID := s.Config().Uuid
    fullPath := filepath.Join(basePath, serverUUID, data.Path)
    // log.Printf("Full path to calculate size: %s", fullPath)

    size, err := calculateFolderSize(fullPath)
    if err != nil {
        // log.Printf("Failed to calculate folder size: %v", err)
        c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to calculate folder size"})
        return
    }

    // log.Printf("Successfully calculated folder size: %d", size)
    c.JSON(http.StatusOK, SizeResponse{Size: size})
}

func calculateFolderSize(path string) (int64, error) {
    var size int64
    err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }
        if !info.IsDir() {
            size += info.Size()
        }
        return nil
    })
    return size, err
}