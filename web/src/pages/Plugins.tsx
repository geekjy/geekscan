import { Table, Tag, Typography, Card, Space } from 'antd';

const plugins = [
  { id: '1', name: 'Nmap', version: '7.94', type: '端口扫描', status: 'active', description: '网络发现和安全审计工具' },
  { id: '2', name: 'Httpx', version: '1.3.7', type: '指纹识别', status: 'active', description: 'HTTP 探测和指纹识别' },
  { id: '3', name: 'Ffuf', version: '2.1.0', type: '目录扫描', status: 'active', description: '快速 Web 模糊测试工具' },
  { id: '4', name: 'Rad', version: '2.0', type: '爬虫', status: 'active', description: '自动化 Web 爬虫工具' },
  { id: '5', name: 'Nuclei', version: '3.1.0', type: '漏洞扫描', status: 'active', description: '基于模板的漏洞扫描器' },
  { id: '6', name: 'Hydra', version: '9.5', type: '暴力破解', status: 'active', description: '网络登录暴力破解工具' },
  { id: '7', name: 'AWVS', version: '24.x', type: '漏洞扫描', status: 'inactive', description: 'Acunetix Web 漏洞扫描器' },
];

const statusMap: Record<string, { color: string; text: string }> = {
  active: { color: 'success', text: '已启用' },
  inactive: { color: 'default', text: '未启用' },
};

export default function Plugins() {
  const columns = [
    { title: '名称', dataIndex: 'name', key: 'name' },
    { title: '版本', dataIndex: 'version', key: 'version' },
    { title: '类型', dataIndex: 'type', key: 'type' },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (s: string) => {
        const info = statusMap[s] || statusMap.inactive;
        return <Tag color={info.color}>{info.text}</Tag>;
      },
    },
    { title: '描述', dataIndex: 'description', key: 'description' },
  ];

  return (
    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
      <Typography.Title level={4}>插件管理</Typography.Title>
      <Card>
        <Table columns={columns} dataSource={plugins} rowKey="id" pagination={false} />
      </Card>
    </Space>
  );
}
