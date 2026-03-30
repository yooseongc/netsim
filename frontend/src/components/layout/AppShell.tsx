import { useEffect, useState, type ReactNode } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Network, FolderOpen, ChevronRight, Home, FlaskConical, ChevronDown } from 'lucide-react';
import { cn } from '@/lib/utils';
import { api } from '@/api/client';
import type { ProjectMeta } from '@/types/project';

interface AppShellProps {
  children: ReactNode;
}

interface SampleItem {
  name: string;
  description: string;
}

export function AppShell({ children }: AppShellProps) {
  const navigate = useNavigate();
  const location = useLocation();
  const [projects, setProjects] = useState<ProjectMeta[]>([]);
  const [samples, setSamples] = useState<SampleItem[]>([]);
  const [projectsOpen, setProjectsOpen] = useState(true);
  const [samplesOpen, setSamplesOpen] = useState(true);

  useEffect(() => {
    api.listProjects()
      .then((res) => setProjects(res.projects))
      .catch(() => {});
  }, [location.pathname]);

  useEffect(() => {
    api.listSamples()
      .then((res) => setSamples(res.samples))
      .catch(() => {});
  }, []);

  // Parse current route
  const pathParts = location.pathname.split('/').filter(Boolean);
  const currentProject = pathParts[0] === 'projects' ? decodeURIComponent(pathParts[1] ?? '') : '';
  const currentSample = pathParts[0] === 'samples' ? decodeURIComponent(pathParts[1] ?? '') : '';
  const isResultPage = pathParts[2] === 'result';

  return (
    <div className="flex h-screen flex-col bg-gray-50 text-gray-900">
      {/* Header */}
      <header className="flex items-center gap-4 border-b border-gray-200 bg-white px-4 py-2.5 shadow-sm flex-shrink-0">
        <button
          onClick={() => navigate('/')}
          className="flex items-center gap-2 text-gray-900 hover:text-gray-600 transition-colors"
        >
          <Network className="h-5 w-5" />
          <span className="text-lg font-bold">netsim</span>
        </button>

        {/* Breadcrumb */}
        {(currentProject || currentSample) && (
          <nav className="flex items-center gap-1 text-sm text-gray-500">
            <ChevronRight className="h-3.5 w-3.5" />
            {currentProject && (
              <button
                onClick={() => navigate(`/projects/${encodeURIComponent(currentProject)}`)}
                className="hover:text-gray-900 transition-colors"
              >
                {currentProject}
              </button>
            )}
            {currentSample && (
              <button
                onClick={() => navigate(`/samples/${encodeURIComponent(currentSample)}`)}
                className="hover:text-gray-900 transition-colors"
              >
                {currentSample}
              </button>
            )}
            {isResultPage && (
              <>
                <ChevronRight className="h-3.5 w-3.5" />
                <span className="text-gray-700">Result</span>
              </>
            )}
          </nav>
        )}
      </header>

      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar */}
        <aside className="hidden w-56 flex-shrink-0 border-r border-gray-200 bg-white md:block overflow-y-auto">
          <div className="p-3">
            <button
              onClick={() => navigate('/')}
              className={cn(
                'flex w-full items-center gap-2 rounded-md px-3 py-2 text-sm font-medium transition-colors',
                location.pathname === '/'
                  ? 'bg-gray-100 text-gray-900'
                  : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900',
              )}
            >
              <Home className="h-4 w-4" />
              All Projects
            </button>
          </div>

          {/* PROJECTS section */}
          <div className="px-3 pb-2">
            <button
              onClick={() => setProjectsOpen(!projectsOpen)}
              className="flex w-full items-center gap-1 px-3 py-1 text-xs font-semibold uppercase text-gray-400 hover:text-gray-600"
            >
              <ChevronDown className={cn('h-3 w-3 transition-transform', !projectsOpen && '-rotate-90')} />
              Projects ({projects.length})
            </button>
            {projectsOpen && (
              <div className="mt-1 space-y-0.5">
                {projects.map((p) => (
                  <button
                    key={p.name}
                    onClick={() => navigate(`/projects/${encodeURIComponent(p.name)}`)}
                    className={cn(
                      'flex w-full items-center gap-2 rounded-md px-3 py-1.5 text-sm transition-colors truncate',
                      currentProject === p.name
                        ? 'bg-gray-100 text-gray-900 font-medium'
                        : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900',
                    )}
                  >
                    <FolderOpen className="h-3.5 w-3.5 flex-shrink-0" />
                    <span className="truncate">{p.name}</span>
                  </button>
                ))}
                {projects.length === 0 && (
                  <div className="px-3 py-1.5 text-xs text-gray-400 italic">No projects yet</div>
                )}
              </div>
            )}
          </div>

          {/* SAMPLES section */}
          {samples.length > 0 && (
            <div className="px-3 pb-3 border-t border-gray-100 pt-2">
              <button
                onClick={() => setSamplesOpen(!samplesOpen)}
                className="flex w-full items-center gap-1 px-3 py-1 text-xs font-semibold uppercase text-gray-400 hover:text-gray-600"
              >
                <ChevronDown className={cn('h-3 w-3 transition-transform', !samplesOpen && '-rotate-90')} />
                Samples ({samples.length})
              </button>
              {samplesOpen && (
                <div className="mt-1 space-y-0.5">
                  {samples.map((s) => (
                    <button
                      key={s.name}
                      onClick={() => navigate(`/samples/${encodeURIComponent(s.name)}`)}
                      className={cn(
                        'flex w-full items-center gap-2 rounded-md px-3 py-1.5 text-sm transition-colors truncate',
                        currentSample === s.name
                          ? 'bg-indigo-50 text-indigo-900 font-medium'
                          : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900',
                      )}
                      title={s.description}
                    >
                      <FlaskConical className="h-3.5 w-3.5 flex-shrink-0 text-indigo-400" />
                      <span className="truncate">{s.name.replace('sample-', '')}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}
        </aside>

        {/* Main content */}
        <main className="flex-1 overflow-hidden">
          {children}
        </main>
      </div>
    </div>
  );
}
