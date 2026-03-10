import { useCallback, useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Card,
  Descriptions,
  Tag,
  Tabs,
  Table,
  Button,
  Space,
  Typography,
  Progress,
  message,
  Spin,
} from 'antd';
import {
  PauseCircleOutlined,
  PlayCircleOutlined,
  FileTextOutlined,
} from '@ant-design/icons';
import { getTask, getResults, pauseTask, resumeTask, type Task, type ScanResult } from '../api/client';

const statusColorMap: Record<string, string> = {
  running: 'processing',
  completed: 'success',
  paused: 'warning',
  failed: 'error',
  pending: 'default',
};

const severityColorMap: Record<string, string> = {
  critical: '#cf1322',
  high: '#fa541c',
  medium: '#faad14',
  low: '#1677ff',
  info: '#8c8c8c',
};

const resultTypes = [
  { key: 'subdomain', label: '子域名' },
  { key: 'port', label: '端口' },
  { key: 'httpx', label: '指纹' },
  { key: 'dir', label: '目录' },
  { key: 'crawl', label: '爬取URL' },
  { key: 'vuln', label: '漏洞' },
  { key: 'brute', label: '暴力破解' },
];

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function flattenData(data: any): Record<string, unknown> {
  if (!data) return {};
  if (Array.isArray(data)) {
    const obj: Record<string, unknown> = {};
    for (const item of data) {
      if (item && typeof item === 'object' && 'Key' in item && 'Value' in item) {
        obj[item.Key] = item.Value;
      }
    }
    return obj;
  }
  if (typeof data === 'object') return data as Record<string, unknown>;
  return {};
}

export default function TaskDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [task, setTask] = useState<Task | null>(null);
  const [results, setResults] = useState<ScanResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('subdomain');

  const fetchData = useCallback(async () => {
    if (!id) return;
    setLoading(true);
    try {
      const [taskRes, resultsRes] = await Promise.all([getTask(id), getResults(id)]);
      setTask(taskRes.data);
      setResults(Array.isArray(resultsRes.data) ? resultsRes.data : []);
    } catch {
      message.error('加载任务详情失败');
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleAction = async (action: 'pause' | 'resume') => {
    if (!id) return;
    try {
      if (action === 'pause') await pauseTask(id);
      else await resumeTask(id);
      message.success(action === 'pause' ? '任务已暂停' : '任务已恢复');
      fetchData();
    } catch {
      message.error('操作失败');
    }
  };

  const subdomainColumns = [
    { title: '子域名', dataIndex: 'host', key: 'host' },
    {
      title: 'IP 地址',
      dataIndex: 'ips',
      key: 'ips',
      render: (ips: string[]) => (ips ?? []).join(', ') || '-',
    },
  ];

  const portColumns = [
    { title: '主机', dataIndex: 'ip', key: 'ip' },
    { title: '端口', dataIndex: 'port', key: 'port' },
    { title: '协议', dataIndex: 'protocol', key: 'protocol' },
    { title: '服务', dataIndex: 'service', key: 'service' },
  ];

  const httpxColumns = [
    { title: '主机', dataIndex: 'host', key: 'host' },
    { title: 'URL', dataIndex: 'url', key: 'url', ellipsis: true },
    { title: '标题', dataIndex: 'title', key: 'title', ellipsis: true },
    { title: '状态码', dataIndex: 'status_code', key: 'status_code' },
    {
      title: '技术栈',
      dataIndex: 'technologies',
      key: 'technologies',
      render: (techs: string[]) => (techs ?? []).map((t) => <Tag key={t}>{t}</Tag>),
    },
  ];

  const dirColumns = [
    { title: '主机', dataIndex: 'host', key: 'host' },
    { title: '路径', dataIndex: 'path', key: 'path', ellipsis: true },
    { title: '状态码', dataIndex: 'status_code', key: 'status_code' },
  ];

  const crawlColumns = [
    { title: '主机', dataIndex: 'host', key: 'host' },
    { title: 'URL', dataIndex: 'url', key: 'url', ellipsis: true },
  ];

  const vulnColumns = [
    { title: '主机', dataIndex: 'host', key: 'host' },
    { title: '漏洞名称', dataIndex: 'name', key: 'name', ellipsis: true },
    {
      title: '等级',
      dataIndex: 'severity',
      key: 'severity',
      render: (s: string) => (
        <Tag color={severityColorMap[s] || '#8c8c8c'}>{(s || 'unknown').toUpperCase()}</Tag>
      ),
    },
    { title: '匹配位置', dataIndex: 'matched_at', key: 'matched_at', ellipsis: true },
  ];

  const bruteColumns = [
    { title: '主机', dataIndex: 'host', key: 'host' },
    { title: '端口', dataIndex: 'port', key: 'port' },
    { title: '服务', dataIndex: 'service', key: 'service' },
    { title: '用户名', dataIndex: 'username', key: 'username' },
    { title: '密码', dataIndex: 'password', key: 'password' },
  ];

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const columnMap: Record<string, any[]> = {
    subdomain: subdomainColumns,
    port: portColumns,
    httpx: httpxColumns,
    dir: dirColumns,
    crawl: crawlColumns,
    vuln: vulnColumns,
    brute: bruteColumns,
  };

  if (loading) {
    return <Spin size="large" style={{ display: 'flex', justifyContent: 'center', marginTop: 100 }} />;
  }

  if (!task) {
    return <Typography.Text type="danger">任务不存在</Typography.Text>;
  }

  return (
    <Space direction="vertical" size="large" style={{ width: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Typography.Title level={4} style={{ margin: 0 }}>{task.name}</Typography.Title>
        <Space>
          {task.status === 'running' && (
            <Button icon={<PauseCircleOutlined />} onClick={() => handleAction('pause')}>
              暂停
            </Button>
          )}
          {task.status === 'paused' && (
            <Button icon={<PlayCircleOutlined />} onClick={() => handleAction('resume')}>
              恢复
            </Button>
          )}
          <Button icon={<FileTextOutlined />} onClick={() => message.info('报告生成功能开发中')}>
            生成报告
          </Button>
          <Button onClick={() => navigate('/tasks')}>返回列表</Button>
        </Space>
      </div>

      <Card>
        <Descriptions column={{ xs: 1, sm: 2, lg: 3 }}>
          <Descriptions.Item label="状态">
            <Tag color={statusColorMap[task.status] || 'default'}>{task.status.toUpperCase()}</Tag>
          </Descriptions.Item>
          <Descriptions.Item label="创建时间">
            {task.created_at ? new Date(task.created_at).toLocaleString() : '-'}
          </Descriptions.Item>
          <Descriptions.Item label="更新时间">
            {task.updated_at ? new Date(task.updated_at).toLocaleString() : '-'}
          </Descriptions.Item>
          <Descriptions.Item label="目标" span={3}>
            {(task.targets ?? []).join(', ')}
          </Descriptions.Item>
        </Descriptions>
        {task.status === 'running' && (
          <Progress percent={task.progress || 0} status="active" style={{ marginTop: 16 }} />
        )}
      </Card>

      <Card>
        <Tabs
          activeKey={activeTab}
          onChange={setActiveTab}
          items={resultTypes.map((rt) => ({
            key: rt.key,
            label: `${rt.label} (${results.filter((r) => r.type === rt.key).length})`,
            children: (
              <Table
                columns={columnMap[rt.key] || portColumns}
                dataSource={results.filter((r) => r.type === rt.key).map((r) => ({ ...flattenData(r.data), _id: r.id }))}
                rowKey="_id"
                size="middle"
                pagination={{ pageSize: 20 }}
              />
            ),
          }))}
        />
      </Card>
    </Space>
  );
}
