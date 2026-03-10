import axios from 'axios';

const api = axios.create({
  baseURL: 'http://localhost:8080/api/v1',
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
});

api.interceptors.response.use(
  (res) => {
    if (res.data && typeof res.data === 'object' && 'data' in res.data) {
      res.data = res.data.data;
    }
    return res;
  },
  (err) => {
    console.error('API Error:', err.response?.data || err.message);
    return Promise.reject(err);
  },
);

export interface Task {
  id: string;
  name: string;
  status: string;
  targets: string[];
  created_at: string;
  updated_at: string;
  progress: number;
  config: Record<string, unknown>;
}

export interface ScanResult {
  id: string;
  task_id: string;
  type: string;
  host: string;
  port?: number;
  protocol?: string;
  service?: string;
  url?: string;
  title?: string;
  status_code?: number;
  technologies?: string[];
  severity?: string;
  vuln_name?: string;
  matched_at?: string;
  path?: string;
  username?: string;
  password?: string;
  created_at: string;
  data: Record<string, unknown>;
}

export interface Provider {
  provider: string;
  configured: boolean;
  api_key?: string;
  api_secret?: string;
  enabled: boolean;
}

export interface Dictionary {
  id: string;
  name: string;
  type: string;
  size: number;
  line_count: number;
  created_at: string;
}

export const getTasks = () => api.get<Task[]>('/tasks');
export const createTask = (data: Record<string, unknown>) => api.post<Task>('/tasks', data);
export const getTask = (id: string) => api.get<Task>(`/tasks/${id}`);
export const pauseTask = (id: string) => api.post(`/tasks/${id}/pause`);
export const resumeTask = (id: string) => api.post(`/tasks/${id}/resume`);
export const deleteTask = (id: string) => api.delete(`/tasks/${id}`);

export const getResults = (taskId: string, type?: string, pageSize = 200) =>
  api.get<ScanResult[]>(`/tasks/${taskId}/results`, { params: { ...(type ? { type } : {}), page_size: pageSize } });

export const getProviders = () => api.get<Provider[]>('/providers');
export const updateProvider = (name: string, data: { api_key?: string; api_secret?: string; enabled?: boolean }) =>
  api.put(`/providers/${name}`, data);
export const deleteProvider = (name: string) => api.delete(`/providers/${name}`);
export const testProvider = (provider: string, apiKey: string) =>
  api.post<{ provider: string; valid: boolean; message?: string }>('/providers/test', { provider, api_key: apiKey });

export const getDictionaries = () => api.get<Dictionary[]>('/dictionaries');
export const uploadDictionary = (file: File, type: string) => {
  const form = new FormData();
  form.append('file', file);
  form.append('type', type);
  return api.post<Dictionary>('/dictionaries', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
};
export const deleteDictionary = (id: string) => api.delete(`/dictionaries/${id}`);
export const previewDictionary = (id: string) =>
  api.get<{ lines: string[] }>(`/dictionaries/${id}/preview`);

export default api;
