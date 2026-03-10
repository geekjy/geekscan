import { useEffect, useState } from 'react';
import { Table, Button, Tag, Space, Popconfirm, message, Typography } from 'antd';
import { PlusOutlined, ReloadOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import { getTasks, pauseTask, resumeTask, deleteTask, type Task } from '../api/client';

const statusColorMap: Record<string, string> = {
  running: 'processing',
  completed: 'success',
  paused: 'warning',
  failed: 'error',
  pending: 'default',
};

export default function TaskList() {
  const [tasks, setTasks] = useState<Task[]>([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  const fetchTasks = () => {
    setLoading(true);
    getTasks()
      .then((res) => setTasks(Array.isArray(res.data) ? res.data : []))
      .catch(() => setTasks([]))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    getTasks()
      .then((res) => setTasks(Array.isArray(res.data) ? res.data : []))
      .catch(() => setTasks([]))
      .finally(() => setLoading(false));
  }, []);

  const handlePauseResume = async (task: Task) => {
    try {
      if (task.status === 'running') {
        await pauseTask(task.id);
        message.success('任务已暂停');
      } else {
        await resumeTask(task.id);
        message.success('任务已恢复');
      }
      fetchTasks();
    } catch {
      message.error('操作失败');
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await deleteTask(id);
      message.success('任务已删除');
      fetchTasks();
    } catch {
      message.error('删除失败');
    }
  };

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
      title: '目标',
      dataIndex: 'targets',
      key: 'targets',
      render: (targets: string[]) => (targets ?? []).join(', ').slice(0, 60) || '-',
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (t: string) => (t ? new Date(t).toLocaleString() : '-'),
    },
    {
      title: '操作',
      key: 'actions',
      render: (_: unknown, record: Task) => (
        <Space>
          <Button size="small" onClick={() => navigate(`/tasks/${record.id}`)}>
            查看
          </Button>
          {(record.status === 'running' || record.status === 'paused') && (
            <Button size="small" onClick={() => handlePauseResume(record)}>
              {record.status === 'running' ? '暂停' : '恢复'}
            </Button>
          )}
          <Popconfirm title="确定删除该任务？" onConfirm={() => handleDelete(record.id)}>
            <Button size="small" danger>删除</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Typography.Title level={4} style={{ margin: 0 }}>扫描任务</Typography.Title>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={fetchTasks}>刷新</Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => navigate('/tasks/new')}>
            新建扫描
          </Button>
        </Space>
      </div>
      <Table
        columns={columns}
        dataSource={tasks}
        rowKey="id"
        loading={loading}
        pagination={{ pageSize: 20 }}
      />
    </Space>
  );
}
