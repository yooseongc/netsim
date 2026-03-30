import type { ProjectMeta, ProjectListResponse, CreateProjectRequest, UpdateProjectRequest, CloneProjectRequest } from '@/types/project';
import type { Scenario, ValidationResult, ImportParseRequest, ImportApplyRequest, ImportResponse } from '@/types/scenario';
import type { SimulationResponse, SimulationResult } from '@/types/trace';

const API_BASE = '/api/v1';

class ApiError extends Error {
  status: number;
  code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: {
      'Content-Type': 'application/json',
    },
    ...options,
  });

  if (!res.ok) {
    let code = 'UNKNOWN';
    let message = `HTTP ${res.status}`;
    try {
      const body = await res.json() as { error?: { code?: string; message?: string } };
      if (body.error) {
        code = body.error.code ?? code;
        message = body.error.message ?? message;
      }
    } catch {
      // ignore parse error
    }
    throw new ApiError(res.status, code, message);
  }

  if (res.status === 204) {
    return undefined as T;
  }

  return res.json() as Promise<T>;
}

function get<T>(path: string): Promise<T> {
  return request<T>(path);
}

function post<T>(path: string, body?: unknown): Promise<T> {
  return request<T>(path, {
    method: 'POST',
    body: body != null ? JSON.stringify(body) : undefined,
  });
}

function put<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, {
    method: 'PUT',
    body: JSON.stringify(body),
  });
}

function del<T>(path: string): Promise<T> {
  return request<T>(path, { method: 'DELETE' });
}

export const api = {
  // Projects
  listProjects: () => get<ProjectListResponse>('/projects'),
  createProject: (data: CreateProjectRequest) => post<ProjectMeta>('/projects', data),
  getProject: (name: string) => get<ProjectMeta>(`/projects/${encodeURIComponent(name)}`),
  updateProject: (name: string, data: UpdateProjectRequest) =>
    put<ProjectMeta>(`/projects/${encodeURIComponent(name)}`, data),
  deleteProject: (name: string) => del<void>(`/projects/${encodeURIComponent(name)}`),
  cloneProject: (name: string, data: CloneProjectRequest) =>
    post<ProjectMeta>(`/projects/${encodeURIComponent(name)}/clone`, data),

  // Scenario
  getScenario: (name: string, format: 'json' | 'yaml' = 'json') =>
    get<Scenario>(`/projects/${encodeURIComponent(name)}/scenario?format=${format}`),
  getScenarioYaml: (name: string) =>
    fetch(`${API_BASE}/projects/${encodeURIComponent(name)}/scenario?format=yaml`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.text();
      }),
  saveScenario: (name: string, data: Scenario) =>
    put<Scenario>(`/projects/${encodeURIComponent(name)}/scenario`, data),
  saveScenarioYaml: (name: string, yaml: string) =>
    fetch(`${API_BASE}/projects/${encodeURIComponent(name)}/scenario`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/x-yaml' },
      body: yaml,
    }).then((r) => {
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return r.json() as Promise<Scenario>;
    }),
  validateScenario: (name: string, data: Scenario) =>
    post<ValidationResult>(`/projects/${encodeURIComponent(name)}/scenario/validate`, data),

  // Simulation
  runSimulation: (name: string, scenarioOverride?: Scenario) =>
    post<SimulationResponse>(`/projects/${encodeURIComponent(name)}/simulate`, {
      scenario_override: scenarioOverride ?? null,
    }),
  getSimulation: (id: string) => get<SimulationResult>(`/simulations/${id}`),

  // Samples
  listSamples: () => get<{ samples: { name: string; description: string }[] }>('/samples'),
  getSample: (name: string) => get<Scenario>(`/samples/${encodeURIComponent(name)}`),
  simulateSample: (name: string) => post<SimulationResult>(`/samples/${encodeURIComponent(name)}/simulate`),

  // Import
  parseImport: (data: ImportParseRequest) =>
    post<ImportResponse>('/import/parse', data),
  applyImport: (name: string, data: ImportApplyRequest) =>
    post<ImportResponse>(`/projects/${encodeURIComponent(name)}/import`, data),
};

export { ApiError };
