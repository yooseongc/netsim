import { useState, useRef, useEffect } from 'react';
import { Plus, LayoutGrid, ChevronDown } from 'lucide-react';
import type { EndpointRole } from '@/types/scenario';

const roles: { value: EndpointRole; label: string }[] = [
  { value: 'local_client', label: 'Local Client' },
  { value: 'remote_client', label: 'Remote Client' },
  { value: 'local_server', label: 'Local Server' },
  { value: 'remote_server', label: 'Remote Server' },
  { value: 'local_proxy', label: 'Local Proxy' },
  { value: 'local_tproxy', label: 'Local TProxy' },
];

interface TopologyToolbarProps {
  onAddEndpoint: (role: EndpointRole) => void;
  onAutoLayout: () => void;
  readOnly?: boolean;
}

export function TopologyToolbar({ onAddEndpoint, onAutoLayout, readOnly }: TopologyToolbarProps) {
  const [open, setOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as HTMLElement)) {
        setOpen(false);
      }
    };
    if (open) document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [open]);

  return (
    <div className="absolute top-3 left-3 z-10 flex items-center gap-2">
      {/* Add Endpoint dropdown */}
      {!readOnly && <div className="relative" ref={dropdownRef}>
        <button
          onClick={() => setOpen(!open)}
          className="inline-flex items-center gap-1.5 rounded-md bg-gray-900 px-3 py-1.5 text-xs font-medium text-white hover:bg-gray-800 shadow-md transition-colors"
        >
          <Plus className="h-3.5 w-3.5" />
          Add Endpoint
          <ChevronDown className="h-3 w-3" />
        </button>

        {open && (
          <div className="absolute top-full mt-1 left-0 w-44 rounded-md border border-gray-200 bg-white shadow-lg py-1">
            <div className="px-3 py-1 text-[10px] font-semibold text-gray-400 uppercase">Inside Device</div>
            {roles.filter((r) => r.value.startsWith('local_')).map((r) => (
              <button
                key={r.value}
                onClick={() => { onAddEndpoint(r.value); setOpen(false); }}
                className="block w-full text-left px-3 py-1.5 text-xs text-gray-700 hover:bg-gray-50"
              >
                {r.label}
              </button>
            ))}
            <div className="border-t border-gray-100 mt-1 pt-1 px-3 py-1 text-[10px] font-semibold text-gray-400 uppercase">Outside Device</div>
            {roles.filter((r) => r.value.startsWith('remote_')).map((r) => (
              <button
                key={r.value}
                onClick={() => { onAddEndpoint(r.value); setOpen(false); }}
                className="block w-full text-left px-3 py-1.5 text-xs text-gray-700 hover:bg-gray-50"
              >
                {r.label}
              </button>
            ))}
          </div>
        )}
      </div>}

      {/* Auto Layout */}
      <button
        onClick={onAutoLayout}
        className="inline-flex items-center gap-1.5 rounded-md bg-white border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-700 hover:bg-gray-50 shadow-md transition-colors"
      >
        <LayoutGrid className="h-3.5 w-3.5" />
        Auto Layout
      </button>
    </div>
  );
}
