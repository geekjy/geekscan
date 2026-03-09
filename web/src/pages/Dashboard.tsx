import { useEffect, useState } from 'react';
import { Row, Col, Card, Statistic, Table, Tag, Typography, Space } from 'antd';
import {
  RadarChartOutlined,
  PlayCircleOutlined,
  BugOutlined,
  ApiOutlined,
} from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import { getTasks, type Task } from '../api/client';

const statusColorMap: Record<string, string> = {
  running: 'processing',
  completed: 'success',
  paused: 'warning',
  failed: 'error',
  pending: 'default',
};

export default function Dashboard() {
  const [tasks, setTasks] = useState<Task[]>([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    getTasks()
      .then((res) => setTasks(res.data ?? []))
      .catch(() => setTasks([]))
      .finally(() => setLoading(false));
  }, []);

  const totalTasks = tasks.length;
  const runningTasks = tasks.filter((t) => t.status === 'running').length;
  const vulnCount = tasks.reduce((sum, t) => sum + (t.progress || 0), 0);

  const columns = [
    {
      title: '任务名称',
      dataIndex: 'name',
      key: 'name',
      render: (name: string, record: Task) => (
        <a onClick={() => navigate(`/tasks/${record.id}`)}>{name}</a>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (status: string) => (
        <Tag color={statusColorMap[status] || 'default'}>{status.toUpperCase()}</Tag>
      ),
    },
    {
      title: '目标数',
      dataIndex: 'targets',
      key: 'targets',
      render: (targets: string[]) => targets?.length || 0,
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (t: string) => (t ? new Date(t).toLocaleString() : '-'),
    },
  ];

  return (
    <Space direction="vertical" size="large" style={{ width: '100%' }}>
      <Typography.Title level={4}>概览</Typography.Title>

      <Row gutter={16}>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic title="总任务数" value={totalTasks} prefix={<RadarChartOutlined />} />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title="运行中"
              value={runningTasks}
              prefix={<PlayCircleOutlined />}
              valueStyle={{ color: '#1677ff' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title="发现漏洞"
              value={vulnCount}
              prefix={<BugOutlined />}
              valueStyle={{ color: '#cf1322' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic title="开放端口" value={0} prefix={<ApiOutlined />} />
          </Card>
        </Col>
      </Row>

      <Card title="最近任务">
        <Table
          columns={columns}
          dataSource={tasks.slice(0, 10)}
          rowKey="id"
          loading={loading}
          pagination={false}
          size="middle"
        />
      </Card>
    </Space>
  );
}
