import {useState} from 'react';
import {NavLink,Routes,Route,Link} from 'react-router-dom';
import {useQuery} from '@tanstack/react-query';
import {ShieldCheck,LayoutDashboard,Database,Radio,Workflow,KeyRound,Menu,Sun,Moon} from 'lucide-react';
import {api,setToken} from './api';
import {Badge,Modal} from './ui';
import {Dashboard,Detection,Alerts,AlertDetail} from './pages';
import {DemoBanner} from './demo';
import {Workspace,ReportPage,Investigations} from './investigation';

export default function App(){const [tokenOpen,showToken]=useState(false),[draft,setDraft]=useState(''),[hasToken,setHasToken]=useState(false),[menu,setMenu]=useState(false),[light,setLight]=useState(false);
  const health=useQuery({queryKey:['health'],queryFn:api.health});
  return <div className={`shell ${light?'light':''}`}><a href="#main" className="skip">跳至主要内容</a><aside className={`sidebar ${menu?'open':''}`}><Link to="/" className="brand"><span className="brand-mark"><ShieldCheck size={24}/></span><span>NetSentry<small>COPILOT / WORKSPACE</small></span></Link><div className="nav-label">安全运营工作台</div><nav aria-label="主导航">{[["/","总览","Overview",LayoutDashboard],["/data","数据与检测","Data & Detection",Database],["/alerts","告警中心","Alert Center",Radio],["/investigations","调查工作区","Investigations",Workflow]].map(([to,zh,en,Icon])=>{const I=Icon as typeof Radio;return <NavLink key={String(to)} to={String(to)} end={to==='/'} onClick={()=>setMenu(false)}><I size={18}/><span>{String(zh)}<small>{String(en)}</small></span></NavLink>})}</nav><div className="sidebar-foot"><span className="status-dot"/> LOCAL DEVELOPMENT<p>证据优先 · 人工复核</p><small>CIDDS-001 / Week 1<br/>非生产安全监控</small></div></aside>
  <div className="main-shell"><header className="topbar"><div className="top-left"><button className="icon-button mobile-menu" aria-label="打开导航" onClick={()=>setMenu(!menu)}><Menu size={21}/></button><span className={`status-dot ${health.isError?'offline':''}`}/><span>{health.isSuccess?'本地服务已连接':health.isError?'后端不可用':'连接本地服务…'}</span><Badge>开发环境</Badge></div><div className="top-actions"><button className="icon-button" aria-label="切换主题" onClick={()=>setLight(!light)}>{light?<Moon size={18}/>:<Sun size={18}/>}</button><button onClick={()=>showToken(true)}><KeyRound size={15}/>{hasToken?'令牌已设置':'本地开发令牌'}</button><span className="avatar">NS</span></div></header>
  <main id="main"><DemoBanner/><Routes><Route path="/" element={<Dashboard/>}/><Route path="/data" element={<Detection/>}/><Route path="/alerts" element={<Alerts/>}/><Route path="/alerts/:aid" element={<AlertDetail/>}/><Route path="/investigations" element={<Investigations/>}/><Route path="/investigations/:iid" element={<Workspace/>}/><Route path="/investigations/:iid/report" element={<ReportPage/>}/><Route path="*" element={<p>页面不存在。<Link to="/">返回总览</Link></p>}/></Routes><footer>NETSENTRY COPILOT <span>Development evidence, human decisions.</span></footer></main></div>
  {tokenOpen&&<Modal title="本地开发令牌" onClose={()=>{showToken(false);setDraft('')}}><p>输入与后端 NETSENTRY_API_TOKEN 相同的令牌。仅保存在当前页面内存；刷新后需要重新输入。</p><form onSubmit={e=>{e.preventDefault();setToken(draft);setHasToken(Boolean(draft));setDraft('');showToken(false)}}><label>写操作令牌<input autoFocus type="password" autoComplete="off" value={draft} onChange={e=>setDraft(e.target.value)}/></label><div className="button-row"><button type="submit" className="primary">保存到内存</button><button type="button" onClick={()=>{setToken('');setHasToken(false);setDraft('');showToken(false)}}>清除令牌</button></div></form></Modal>}
  </div>
}
