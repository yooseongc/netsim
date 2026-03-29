import { useEffect, useState, type ReactNode } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Network, FolderOpen, ChevronRight, Home } from 'lucide-react';
import { cn } from '@/lib/utils';
import { api } from '@/api/client';
import type { ProjectMeta } from '@/types/project';

interface AppShellProps {
  children: ReactNode;
}

export function AppShell({ children }: AppShellProps) {
  const navigate = useNavigate();
  const location = useLocation();
  const [projects, setProjects] = useState<ProjectMeta[]>([]);

  useEffect(() => {
    api.listProjects()
      .then((res) => setProjects(res.projects))
      .catch(() => {
        // Silently fail — sidebar projects are supplementary
      });
  }, [location.pathname]);

  // Parse current route for breadcrumb
  const pathParts = location.pathname.split('/').filter(Boolean);
  const currentProject = pathParts[0] === 'projects' ? decodeURIComponent(pathParts[1] ?? '') : '';
  const isResultPage = pathParts[2] === 'result';

  return (
    <div className="flex h-screen flex-col bg-gray-50 text-gray-900">
      {/* Header */}
      <header className="flex items-center gap-4 border-b border-gray-200 bg-white px-4 py-2.5 shadow-sm">
        <button
          onClick={() => navigate('/')}
          className="flex items-center gap-2 text-gray-900 hover:text-gray-600 transition-colors"
        >
          <Network className="h-5 w-5" />
          <span className="text-lg font-bold">netsim</span>
        </button>

        {/* Breadcrumb */}
        {currentProject && (
          <nav className="flex items-center gap-1 text-sm text-gray-500">
            <ChevronRight className="h-3.5 w-3.5" />
            <button
              onClick={() => navigate(`/projects/${encodeURIComponent(currentProject)}`)}
              className="hover:text-gray-900 transition-colors"
            >
              {currentProject}
            </button>
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

          {projects.length > 0 && (
            <div className="px-3 pb-3">
              <div className="mb-1 px-3 text-xs font-medium uppercase text-gray-400">Projects</div>
              <div className="space-y-0.5">
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
              </div>
            </div>
          )}
        </aside>

        {/* Main content */}
        <main className="flex-1 overflow-y-auto p-6">
          {children}
        </main>
      </div>
    </div>
  );
}
