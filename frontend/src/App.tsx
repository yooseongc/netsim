import { Routes, Route } from 'react-router-dom';
import { AppShell } from './components/layout/AppShell';
import { SimulationProvider } from './contexts/SimulationContext';
import { ProjectListPage } from './pages/ProjectListPage';
import { ScenarioEditorPage } from './pages/ScenarioEditorPage';
import { SimulationResultPage } from './pages/SimulationResultPage';
import { ImportPage } from './pages/ImportPage';
import { SampleViewerPage } from './pages/SampleViewerPage';

export default function App() {
  return (
    <SimulationProvider>
      <AppShell>
        <Routes>
          <Route path="/" element={<ProjectListPage />} />
          <Route path="/projects/:name" element={<ScenarioEditorPage />} />
          <Route path="/projects/:name/result" element={<SimulationResultPage />} />
          <Route path="/projects/:name/import" element={<ImportPage />} />
          <Route path="/samples/:name" element={<SampleViewerPage />} />
        </Routes>
      </AppShell>
    </SimulationProvider>
  );
}
