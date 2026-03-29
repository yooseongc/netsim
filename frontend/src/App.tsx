import { Routes, Route } from 'react-router-dom';
import { AppShell } from './components/layout/AppShell';
import { SimulationProvider } from './contexts/SimulationContext';
import { ProjectListPage } from './pages/ProjectListPage';
import { ScenarioEditorPage } from './pages/ScenarioEditorPage';
import { SimulationResultPage } from './pages/SimulationResultPage';

export default function App() {
  return (
    <SimulationProvider>
      <AppShell>
        <Routes>
          <Route path="/" element={<ProjectListPage />} />
          <Route path="/projects/:name" element={<ScenarioEditorPage />} />
          <Route path="/projects/:name/result" element={<SimulationResultPage />} />
        </Routes>
      </AppShell>
    </SimulationProvider>
  );
}
