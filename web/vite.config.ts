import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // 监听所有 IPv4 地址，允许局域网内其他设备访问
    host: '0.0.0.0',
    // 可选：指定端口，默认是 5173
    port: 5173 
  }
})