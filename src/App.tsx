import { HashRouter, Route, Routes } from 'react-router-dom';
import AppShell from './components/AppShell';
import { TenantProvider } from './lib/TenantContext';
import ExecutiveOverview from './pages/ExecutiveOverview';
import BusinessUnitRiskPage from './pages/BusinessUnitRisk';
import Roadmap from './pages/Roadmap';
import IdentityRisk from './pages/IdentityRisk';
import PrivilegedAccess from './pages/PrivilegedAccess';
import Governance from './pages/Governance';
import WorkloadIdentity from './pages/WorkloadIdentity';
import Resilience from './pages/Resilience';
import Findings from './pages/Findings';

export default function App() {
  return (
    <TenantProvider>
      <HashRouter>
        <Routes>
          <Route element={<AppShell />}>
            <Route index element={<ExecutiveOverview />} />
            <Route path="business-units" element={<BusinessUnitRiskPage />} />
            <Route path="roadmap" element={<Roadmap />} />
            <Route path="identity-risk" element={<IdentityRisk />} />
            <Route path="privileged-access" element={<PrivilegedAccess />} />
            <Route path="governance" element={<Governance />} />
            <Route path="workload-identity" element={<WorkloadIdentity />} />
            <Route path="resilience" element={<Resilience />} />
            <Route path="findings" element={<Findings />} />
            <Route path="*" element={<ExecutiveOverview />} />
          </Route>
        </Routes>
      </HashRouter>
    </TenantProvider>
  );
}
