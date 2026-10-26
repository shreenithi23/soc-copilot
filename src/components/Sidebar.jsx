import React from 'react';
import { 
  LayoutDashboard, 
  AlertTriangle, 
  Terminal, 
  FileText, 
  Users, 
  Shield, 
  Activity, 
  Settings,
  Sparkles,
  Database,
  Radio
} from 'lucide-react';

export default function Sidebar({ activeTab, setActiveTab, stats }) {
  const navItems = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'stream', label: 'Live Stream & Correlate', icon: Radio, badge: 'LIVE', badgeType: 'low' },
    { id: 'alerts', label: 'Unified Alert Center', icon: AlertTriangle, badge: stats?.critical_alerts > 0 ? stats.critical_alerts : (stats?.total_logs || null), badgeType: stats?.critical_alerts > 0 ? 'danger' : '' },
    { id: 'investigations', label: 'Aegis Threat Hunting', icon: Terminal, highlight: true },
    { id: 'iam', label: 'Identities & Access', icon: Users },
    { id: 'intel', label: 'Context-Rich Intel', icon: Shield, badge: stats?.vt_malicious > 0 ? stats.vt_malicious : null, badgeType: 'danger' },
    { id: 'audit', label: 'Audit & Governance', icon: Activity },
    { id: 'settings', label: 'Platform & Pipeline', icon: Settings },
  ];

  return (
    <aside className="app-sidebar" aria-label="Main Navigation">
      
      {/* HarkX Brand Header with Official Logo */}
      <div className="sidebar-header">
        <svg className="sidebar-logo-svg" viewBox="0 0 24 39" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M22.8845 3.0994C22.9592 4.53233 23.2913 11.2603 22.8489 13.4643C22.7868 13.7723 22.7075 14.0584 22.7075 14.0584C22.3123 15.4821 21.6067 16.5427 21.0195 17.2552C20.684 17.7125 20.3025 18.1664 19.867 18.6065C16.5932 21.9286 12.5828 22.2549 11.6451 22.3055C10.0755 22.3055 8.52417 22.9398 7.42104 24.0625C7.33945 24.1441 7.26131 24.2268 7.11422 24.4566C6.51669 25.3931 6.20644 26.4848 6.20644 27.596V32.0177C6.20644 33.7023 4.89646 35.1398 3.21303 35.1961C1.4526 35.2547 0.00817871 33.8459 0.00817871 32.0993V25.5494C0.0219679 25.3632 0.0507028 25.0725 0.116202 24.7209C0.454038 22.9145 1.38021 21.6448 1.92259 20.9174C2.0961 20.6841 2.51322 20.1567 3.00963 19.6522C6.28572 16.3279 10.2961 16.0038 11.2315 15.9533C12.8034 15.9533 14.3536 15.296 15.4567 14.1963C16.2438 13.4068 16.6851 12.3382 16.6851 11.2236V3.17639C16.6851 1.46883 18.033 0.0232571 19.7406 0.000275039C20.6139 -0.011216 21.4056 0.338107 21.9756 0.908061C22.5363 1.46882 22.8822 2.24332 22.8822 3.09826H22.8845V3.0994Z" fill="url(#harkx_sidebar_grad1)" />
          <path d="M22.8948 25.5482V35.2788C22.8948 36.8945 21.6859 38.2941 20.0772 38.4366C18.2386 38.5997 16.6954 37.1553 16.6954 35.3489V27.1076C16.6954 25.978 16.2725 24.8783 15.475 24.0785C15.4693 24.0728 15.4647 24.0682 15.4589 24.0624C14.3558 22.9398 12.8057 22.3055 11.2348 22.3055C10.2972 22.2549 6.28796 21.9286 3.01302 18.6065C2.4063 17.9917 1.90873 17.3218 1.82829 17.2092C1.63639 16.9438 1.46288 16.6806 1.30546 16.4221C0.436736 14.9949 -0.00681545 13.3494 7.91589e-05 11.6774C0.00697377 9.91126 0.0138605 8.77595 0.0207551 7.00978C0.0207551 5.29761 1.40773 3.91064 3.11989 3.91064C3.97597 3.91064 4.75161 4.25653 5.31238 4.81729C5.87429 5.37805 6.22132 6.1537 6.22132 7.00978V11.2281C6.22132 12.329 6.63384 13.3988 7.40949 14.1802C7.41408 14.1848 7.41983 14.1905 7.42442 14.1951C8.52756 15.2948 10.0777 15.9521 11.6485 15.9521C12.585 16.0026 16.5954 16.3278 19.8703 19.651C20.3013 20.0889 20.6805 20.5382 21.0137 20.992C21.6606 21.8723 22.3719 22.8237 22.7075 24.198C22.8431 24.7519 22.8833 25.2253 22.8948 25.5471V25.5482Z" fill="url(#harkx_sidebar_grad2)" />
          <defs>
            <linearGradient id="harkx_sidebar_grad1" x1="0.99" y1="37.25" x2="27.46" y2="-8.59" gradientUnits="userSpaceOnUse">
              <stop offset="0.14" stopColor="#00529E" />
              <stop offset="0.55" stopColor="#008E8A" />
              <stop offset="0.78" stopColor="#2FA361" />
              <stop offset="1" stopColor="#6ABF2F" />
            </linearGradient>
            <linearGradient id="harkx_sidebar_grad2" x1="11.44" y1="37.15" x2="11.44" y2="2.62" gradientUnits="userSpaceOnUse">
              <stop stopColor="#00529E" />
              <stop offset="0.54" stopColor="#008E8A" />
              <stop offset="1" stopColor="#6ABF2F" />
            </linearGradient>
          </defs>
        </svg>

        <div className="sidebar-title-group">
          <span className="sidebar-title">
            Aegis <span className="brand-gradient">AI</span>
          </span>
          <span className="sidebar-version">Autonomous Threat Defense</span>
        </div>
      </div>

      <nav className="sidebar-nav">
        <div className="sidebar-nav-section-label">AI SOC Platform</div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              className={`sidebar-nav-item ${isActive ? 'active' : ''}`}
              onClick={() => setActiveTab(item.id)}
              aria-current={isActive ? 'page' : undefined}
            >
              <div className="sidebar-nav-label-group">
                <Icon size={15} />
                <span>{item.label}</span>
              </div>
              {item.badge !== null && item.badge !== undefined && (
                <span className={`sidebar-nav-badge ${item.badgeType || ''}`}>
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>
    </aside>
  );
}
