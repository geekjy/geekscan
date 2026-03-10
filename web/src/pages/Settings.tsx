import { useEffect, useState } from 'react';
import {
  Tabs,
  Table,
  Button,
  Input,
  Switch,
  Space,
  Typography,
  Card,
  message,
  Popconfirm,
  Upload,
  Select,
  Modal,
  Form,
} from 'antd';
import { UploadOutlined, EyeOutlined, DeleteOutlined, CheckCircleOutlined } from '@ant-design/icons';
import {
  getProviders,
  updateProvider,
  testProvider,
  getDictionaries,
  uploadDictionary,
  deleteDictionary,
  previewDictionary,
  type Provider,
  type Dictionary,
} from '../api/client';

const providerTypeMap: Record<string, string> = {
  shodan: '网络空间搜索',
  censys: '网络空间搜索',
  fofa: '网络空间搜索',
  hunter: '网络空间搜索',
  quake: '网络空间搜索',
  zoomeye: '网络空间搜索',
  binaryedge: '网络空间搜索',
  virustotal: '威胁情报',
  securitytrails: '威胁情报',
  passivetotal: '威胁情报',
  chaos: '子域名枚举',
  github: '代码托管',
  gitlab: '代码托管',
  awvs: '漏洞扫描器',
};

function DataSourcesTab() {
  const [providers, setProviders] = useState<Provider[]>([]);
  const [loading, setLoading] = useState(true);
  const [testing, setTesting] = useState<string | null>(null);
  const [editedKeys, setEditedKeys] = useState<Record<string, string>>({});

  const fetchProviders = () => {
    setLoading(true);
    getProviders()
      .then((res) => setProviders(Array.isArray(res.data) ? res.data : []))
      .catch(() => setProviders([]))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchProviders();
  }, []);

  const handleToggle = async (record: Provider, enabled: boolean) => {
    try {
      await updateProvider(record.provider, { enabled });
      message.success(`${record.provider} 已${enabled ? '启用' : '禁用'}`);
      fetchProviders();
    } catch {
      message.error('操作失败');
    }
  };

  const handleSaveKey = async (record: Provider, apiKey: string) => {
    try {
      await updateProvider(record.provider, { api_key: apiKey });
      message.success('API Key 已保存');
      fetchProviders();
    } catch {
      message.error('保存失败');
    }
  };

  const handleTest = async (record: Provider) => {
    const apiKey = editedKeys[record.provider] || record.api_key || '';
    if (!apiKey) {
      message.warning('请先输入 API Key');
      return;
    }
    setTesting(record.provider);
    try {
      const res = await testProvider(record.provider, apiKey);
      if (res.data.valid) message.success('连接测试成功');
      else message.error(res.data.message || '连接测试失败');
    } catch {
      message.error('连接测试失败');
    } finally {
      setTesting(null);
    }
  };

  const columns = [
    {
      title: '名称',
      dataIndex: 'provider',
      key: 'provider',
      render: (name: string) => <span style={{ fontWeight: 500 }}>{name}</span>,
    },
    {
      title: '类型',
      key: 'type',
      render: (_: unknown, record: Provider) => providerTypeMap[record.provider] || '-',
    },
    {
      title: 'API Key',
      key: 'api_key',
      render: (_: unknown, record: Provider) => (
        <Input.Password
          defaultValue={record.api_key}
          placeholder="输入 API Key"
          style={{ width: 240 }}
          onChange={(e) =>
            setEditedKeys((prev) => ({ ...prev, [record.provider]: e.target.value }))
          }
          onBlur={(e) => {
            const val = e.target.value;
            if (val && val !== record.api_key) {
              handleSaveKey(record, val);
            }
          }}
        />
      ),
    },
    {
      title: '状态',
      key: 'enabled',
      render: (_: unknown, record: Provider) => (
        <Switch checked={record.enabled} onChange={(v) => handleToggle(record, v)} />
      ),
    },
    {
      title: '操作',
      key: 'actions',
      render: (_: unknown, record: Provider) => (
        <Button
          icon={<CheckCircleOutlined />}
          loading={testing === record.provider}
          onClick={() => handleTest(record)}
          size="small"
        >
          测试
        </Button>
      ),
    },
  ];

  return (
    <Table
      columns={columns}
      dataSource={providers}
      rowKey="provider"
      loading={loading}
      pagination={false}
    />
  );
}

function DictionariesTab() {
  const [dicts, setDicts] = useState<Dictionary[]>([]);
  const [loading, setLoading] = useState(true);
  const [previewVisible, setPreviewVisible] = useState(false);
  const [previewLines, setPreviewLines] = useState<string[]>([]);
  const [previewTitle, setPreviewTitle] = useState('');
  const [uploadType, setUploadType] = useState('directory');

  const fetchDicts = () => {
    setLoading(true);
    getDictionaries()
      .then((res) => setDicts(Array.isArray(res.data) ? res.data : []))
      .catch(() => setDicts([]))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    getDictionaries()
      .then((res) => setDicts(Array.isArray(res.data) ? res.data : []))
      .catch(() => setDicts([]))
      .finally(() => setLoading(false));
  }, []);

  const handlePreview = async (dict: Dictionary) => {
    try {
      const res = await previewDictionary(dict.id);
      setPreviewLines(res.data.lines ?? []);
      setPreviewTitle(dict.name);
      setPreviewVisible(true);
    } catch {
      message.error('预览失败');
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await deleteDictionary(id);
      message.success('已删除');
      fetchDicts();
    } catch {
      message.error('删除失败');
    }
  };

  const columns = [
    { title: '名称', dataIndex: 'name', key: 'name' },
    { title: '类型', dataIndex: 'type', key: 'type' },
    { title: '行数', dataIndex: 'line_count', key: 'line_count' },
    {
      title: '大小',
      dataIndex: 'size',
      key: 'size',
      render: (s: number) => `${(s / 1024).toFixed(1)} KB`,
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
      render: (_: unknown, record: Dictionary) => (
        <Space>
          <Button size="small" icon={<EyeOutlined />} onClick={() => handlePreview(record)}>
            预览
          </Button>
          <Popconfirm title="确定删除？" onConfirm={() => handleDelete(record.id)}>
            <Button size="small" danger icon={<DeleteOutlined />}>删除</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <>
      <Space style={{ marginBottom: 16 }}>
        <Select value={uploadType} onChange={setUploadType} style={{ width: 120 }} options={[
          { value: 'directory', label: '目录字典' },
          { value: 'password', label: '密码字典' },
          { value: 'subdomain', label: '子域名字典' },
        ]} />
        <Upload
          showUploadList={false}
          customRequest={async ({ file, onSuccess, onError }) => {
            try {
              await uploadDictionary(file as File, uploadType);
              message.success('上传成功');
              fetchDicts();
              onSuccess?.(null);
            } catch {
              message.error('上传失败');
              onError?.(new Error('upload failed'));
            }
          }}
        >
          <Button icon={<UploadOutlined />}>上传字典</Button>
        </Upload>
      </Space>
      <Table columns={columns} dataSource={dicts} rowKey="id" loading={loading} pagination={false} />
      <Modal
        title={`预览: ${previewTitle}`}
        open={previewVisible}
        onCancel={() => setPreviewVisible(false)}
        footer={null}
        width={600}
      >
        <pre style={{ maxHeight: 400, overflow: 'auto', fontSize: 12, background: '#fafafa', padding: 12 }}>
          {previewLines.join('\n')}
        </pre>
      </Modal>
    </>
  );
}

function AwvsTab() {
  const [form] = Form.useForm();
  const [testing, setTesting] = useState(false);

  const handleTest = async () => {
    setTesting(true);
    try {
      await form.validateFields();
      message.info('AWVS 连接测试功能开发中');
    } catch {
      // validation failed
    } finally {
      setTesting(false);
    }
  };

  return (
    <Form form={form} layout="vertical" style={{ maxWidth: 480 }}>
      <Form.Item name="awvs_url" label="AWVS URL" rules={[{ required: true, message: '请输入 AWVS 地址' }]}>
        <Input placeholder="https://awvs.example.com:3443" />
      </Form.Item>
      <Form.Item name="awvs_api_key" label="API Key" rules={[{ required: true, message: '请输入 API Key' }]}>
        <Input.Password placeholder="输入 AWVS API Key" />
      </Form.Item>
      <Form.Item>
        <Space>
          <Button type="primary" loading={testing} onClick={handleTest}>
            测试连接
          </Button>
          <Button onClick={() => message.info('保存功能开发中')}>保存</Button>
        </Space>
      </Form.Item>
    </Form>
  );
}

export default function Settings() {
  return (
    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
      <Typography.Title level={4}>系统设置</Typography.Title>
      <Card>
        <Tabs items={[
          { key: 'datasources', label: '数据源', children: <DataSourcesTab /> },
          { key: 'dictionaries', label: '字典管理', children: <DictionariesTab /> },
          { key: 'awvs', label: 'AWVS', children: <AwvsTab /> },
        ]} />
      </Card>
    </Space>
  );
}
