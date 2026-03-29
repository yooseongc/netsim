import type { ReactNode } from 'react'

interface AppShellProps {
  children: ReactNode
}

export function AppShell({ children }: AppShellProps) {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <header className="border-b px-6 py-3">
        <h1 className="text-xl font-bold">netsim</h1>
      </header>
      <main className="p-6">
        {children}
      </main>
    </div>
  )
}
