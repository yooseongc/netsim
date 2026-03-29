export interface ProjectMeta {
  name: string;
  description: string | null;
  created_at: string;
  updated_at: string;
  has_scenario?: boolean;
  has_imported_config?: boolean;
}

export interface ProjectListResponse {
  projects: ProjectMeta[];
}

export interface CreateProjectRequest {
  name: string;
  description?: string | null;
}

export interface UpdateProjectRequest {
  description?: string | null;
}

export interface CloneProjectRequest {
  new_name: string;
}
