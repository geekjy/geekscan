import { Component, StrictMode, type ReactNode } from 'react'
import { createRoot } from 'react-dom/client'
import { ConfigProvider, Result, Button, Typography } from 'antd'
import zhCN from 'antd/locale/zh_CN'
import App from './App'
import './index.css'

class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state: { error: Error | null } = { error: null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  render() {
    if (this.state.error) {
      return (
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh' }}>
          <Result
            status="error"
            title="页面渲染出错"
            subTitle={<Typography.Text type="secondary">{this.state.error.message}</Typography.Text>}
            extra={<Button type="primary" onClick={() => window.location.reload()}>刷新页面</Button>}
          />
        </div>
      );
    }
    return this.props.children;
  }
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ErrorBoundary>
      <ConfigProvider locale={zhCN}>
        <App />
      </ConfigProvider>
    </ErrorBoundary>
  </StrictMode>,
)
