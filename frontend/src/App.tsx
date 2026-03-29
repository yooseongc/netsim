import { Routes, Route } from 'react-router-dom'
import { AppShell } from './components/layout/AppShell'
import { ProjectListPage } from './pages/ProjectListPage'

export default function App() {
  return (
    <AppShell>
      <Routes>
        <Route path="/" element={<ProjectListPage />} />
      </Routes>
    </AppShell>
  )
}
