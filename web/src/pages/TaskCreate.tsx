import { useState } from 'react';
import {
  Form,
  Input,
  Button,
  Tabs,
  Select,
  Switch,
  InputNumber,
  Checkbox,
  Typography,
  Card,
  Space,
  message,
} from 'antd';
import { useNavigate } from 'react-router-dom';
import { createTask, getDictionaries, type Dictionary } from '../api/client';
import { useEffect } from 'react';

export default function TaskCreate() {
  const [form] = Form.useForm();
  const [submitting, setSubmitting] = useState(false);
  const [dictionaries, setDictionaries] = useState<Dictionary[]>([]);
  const navigate = useNavigate();

  useEffect(() => {
    getDictionaries()
      .then((res) => setDictionaries(Array.isArray(res.data) ? res.data : []))
      .catch(() => {});
  }, []);

  const handleSubmit = async () => {
    try {
      const values = await form.validateFields();
      setSubmitting(true);

      const targets = (values.targets as string)
        .split('\n')
        .map((t: string) => t.trim())
        .filter(Boolean);

      const payload = {
        name: values.name,
        targets,
        config: {
          port_scan: {
            strategy: values.port_strategy || 'top1000',
            scan_type: values.scan_type || 'syn',
            udp: values.udp || false,
            rate: values.port_rate || 1000,
            threads: values.port_threads || 100,
          },
          httpx: {
            threads: values.httpx_threads || 50,
            tech_detect: values.tech_detect ?? true,
            screenshot: values.screenshot || false,
          },
          ffuf: {
            dictionary_id: values.dictionary_id,
            threads: values.ffuf_threads || 40,
            extensions: values.extensions || '',
            recursion: values.recursion || false,
          },
          rad: {
            enabled: values.rad_enabled || false,
            max_time: values.rad_max_time || 300,
            max_crawl: values.rad_max_crawl || 1000,
            max_depth: values.rad_max_depth || 5,
          },
          nuclei: {
            max_time: values.nuclei_max_time || 600,
            severity: values.nuclei_severity || ['critical', 'high'],
            auto_fingerprint: values.auto_fingerprint ?? true,
          },
          brute: {
            enabled: values.brute_enabled || false,
            services: values.brute_services || [],
            stop_on_first: values.stop_on_first || false,
          },
          awvs: {
            enabled: values.awvs_enabled || false,
            scan_profile: values.scan_profile || 'full',
          },
        },
      };

      await createTask(payload);
      message.success('扫描任务创建成功');
      navigate('/tasks');
    } catch {
      message.error('创建失败，请检查表单');
    } finally {
      setSubmitting(false);
    }
  };

  const tabItems = [
    {
      key: 'basic',
      label: '基本信息',
      children: (
        <Space direction="vertical" style={{ width: '100%' }} size="middle">
          <Form.Item name="name" label="任务名称" rules={[{ required: true, message: '请输入任务名称' }]}>
            <Input placeholder="输入扫描任务名称" />
          </Form.Item>
          <Form.Item name="targets" label="扫描目标" rules={[{ required: true, message: '请输入扫描目标' }]}>
            <Input.TextArea rows={6} placeholder="每行一个目标，支持 IP、CIDR、域名" />
          </Form.Item>
        </Space>
      ),
    },
    {
      key: 'portscan',
      label: '端口扫描',
      children: (
        <Space direction="vertical" style={{ width: '100%' }} size="middle">
          <Form.Item name="port_strategy" label="端口策略" initialValue="top1000">
            <Select options={[
              { value: 'top100', label: 'Top 100' },
              { value: 'top1000', label: 'Top 1000' },
              { value: 'full', label: '全端口 (1-65535)' },
              { value: 'custom', label: '自定义' },
            ]} />
          </Form.Item>
          <Form.Item name="scan_type" label="扫描类型" initialValue="syn">
            <Select options={[
              { value: 'syn', label: 'SYN 扫描' },
              { value: 'connect', label: 'Connect 扫描' },
            ]} />
          </Form.Item>
          <Form.Item name="udp" label="UDP 扫描" valuePropName="checked">
            <Switch />
          </Form.Item>
          <Form.Item name="port_rate" label="扫描速率" initialValue={1000}>
            <InputNumber min={1} max={100000} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="port_threads" label="线程数" initialValue={100}>
            <InputNumber min={1} max={1000} style={{ width: '100%' }} />
          </Form.Item>
        </Space>
      ),
    },
    {
      key: 'httpx',
      label: 'Httpx',
      children: (
        <Space direction="vertical" style={{ width: '100%' }} size="middle">
          <Form.Item name="httpx_threads" label="线程数" initialValue={50}>
            <InputNumber min={1} max={500} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="tech_detect" label="技术识别" valuePropName="checked" initialValue={true}>
            <Switch />
          </Form.Item>
          <Form.Item name="screenshot" label="网页截图" valuePropName="checked">
            <Switch />
          </Form.Item>
        </Space>
      ),
    },
    {
      key: 'ffuf',
      label: 'Ffuf',
      children: (
        <Space direction="vertical" style={{ width: '100%' }} size="middle">
          <Form.Item name="dictionary_id" label="字典">
            <Select
              placeholder="选择字典"
              allowClear
              options={dictionaries.map((d) => ({ value: d.id, label: `${d.name} (${d.line_count} 行)` }))}
            />
          </Form.Item>
          <Form.Item name="ffuf_threads" label="线程数" initialValue={40}>
            <InputNumber min={1} max={500} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="extensions" label="扩展名">
            <Input placeholder="例如: php,asp,jsp,html" />
          </Form.Item>
          <Form.Item name="recursion" label="递归扫描" valuePropName="checked">
            <Switch />
          </Form.Item>
        </Space>
      ),
    },
    {
      key: 'rad',
      label: 'Rad',
      children: (
        <Space direction="vertical" style={{ width: '100%' }} size="middle">
          <Form.Item name="rad_enabled" label="启用" valuePropName="checked">
            <Switch />
          </Form.Item>
          <Form.Item name="rad_max_time" label="最大时间 (秒)" initialValue={300}>
            <InputNumber min={1} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="rad_max_crawl" label="最大爬取数" initialValue={1000}>
            <InputNumber min={1} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="rad_max_depth" label="最大深度" initialValue={5}>
            <InputNumber min={1} max={20} style={{ width: '100%' }} />
          </Form.Item>
        </Space>
      ),
    },
    {
      key: 'nuclei',
      label: 'Nuclei',
      children: (
        <Space direction="vertical" style={{ width: '100%' }} size="middle">
          <Form.Item name="nuclei_max_time" label="最大时间 (秒)" initialValue={600}>
            <InputNumber min={1} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="nuclei_severity" label="漏洞等级" initialValue={['critical', 'high']}>
            <Checkbox.Group options={[
              { label: 'Critical', value: 'critical' },
              { label: 'High', value: 'high' },
              { label: 'Medium', value: 'medium' },
              { label: 'Low', value: 'low' },
              { label: 'Info', value: 'info' },
            ]} />
          </Form.Item>
          <Form.Item name="auto_fingerprint" label="自动指纹匹配" valuePropName="checked" initialValue={true}>
            <Switch />
          </Form.Item>
        </Space>
      ),
    },
    {
      key: 'brute',
      label: '暴力破解',
      children: (
        <Space direction="vertical" style={{ width: '100%' }} size="middle">
          <Form.Item name="brute_enabled" label="启用" valuePropName="checked">
            <Switch />
          </Form.Item>
          <Form.Item name="brute_services" label="目标服务">
            <Checkbox.Group options={[
              { label: 'SSH', value: 'ssh' },
              { label: 'FTP', value: 'ftp' },
              { label: 'MySQL', value: 'mysql' },
              { label: 'PostgreSQL', value: 'postgres' },
              { label: 'Redis', value: 'redis' },
              { label: 'MongoDB', value: 'mongodb' },
              { label: 'MSSQL', value: 'mssql' },
              { label: 'RDP', value: 'rdp' },
            ]} />
          </Form.Item>
          <Form.Item name="stop_on_first" label="首次命中即停" valuePropName="checked">
            <Switch />
          </Form.Item>
        </Space>
      ),
    },
    {
      key: 'awvs',
      label: 'AWVS',
      children: (
        <Space direction="vertical" style={{ width: '100%' }} size="middle">
          <Form.Item name="awvs_enabled" label="启用" valuePropName="checked">
            <Switch />
          </Form.Item>
          <Form.Item name="scan_profile" label="扫描配置" initialValue="full">
            <Select options={[
              { value: 'full', label: '完整扫描' },
              { value: 'high_risk', label: '高风险漏洞' },
              { value: 'xss', label: 'XSS 检测' },
              { value: 'sql_injection', label: 'SQL 注入' },
              { value: 'weak_password', label: '弱口令检测' },
              { value: 'crawl_only', label: '仅爬取' },
            ]} />
          </Form.Item>
        </Space>
      ),
    },
  ];

  return (
    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
      <Typography.Title level={4}>新建扫描任务</Typography.Title>
      <Card>
        <Form form={form} layout="vertical" style={{ maxWidth: 720 }}>
          <Tabs items={tabItems} />
          <Form.Item style={{ marginTop: 16 }}>
            <Space>
              <Button type="primary" loading={submitting} onClick={handleSubmit}>
                创建任务
              </Button>
              <Button onClick={() => navigate('/tasks')}>取消</Button>
            </Space>
          </Form.Item>
        </Form>
      </Card>
    </Space>
  );
}
