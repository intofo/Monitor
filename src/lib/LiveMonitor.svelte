<script lang="ts">
  import { t, language, theme } from './preferences';
  import { invoke, isTauri } from '@tauri-apps/api/core';
  import { open } from '@tauri-apps/plugin-dialog';
  import { onMount } from 'svelte';
  import { getCurrentWindow } from '@tauri-apps/api/window';
  import DevelopmentPermissions from './DevelopmentPermissions.svelte';
  import AgentIcon from './AgentIcon.svelte';
  import AuditLog from './AuditLog.svelte';
  import JevSettings from './JevSettings.svelte';
  import SystemExtensionStatus from './SystemExtensionStatus.svelte';
  import ProtectionSettings from './ProtectionSettings.svelte';
  import PacketCapture from './PacketCapture.svelte';
  type Process = {pid:number;name:string;executable:string;agent:string;agent_id:string;inherited:boolean;start_time:number;parent:number|null};
  type Agent = {id:string;name:string;paths:string[];installed:boolean;running:number;enabled:boolean;custom:boolean};
  type Activity = {pid:number;agent_id:string;kind:string;target:string};
  type Snapshot = {activities:Activity[];at_ms:number;running:boolean;config_revision:number;agents:Agent[];processes:Process[];warnings:string[]};
  type Config = {revision:number;close_to_tray:boolean;enabled:Record<string,boolean>};
  let snapshot=$state<Snapshot|null>(null);let config=$state<Config|null>(null);
  let error=$state('');let busy=$state(false);
  let selected=$state('');let detail=$state('protection');
  let adding=$state(false);let name=$state('');let executable=$state('');
  let settingsDialog:HTMLDialogElement;
  let authorizationDialog:HTMLDialogElement;
  let startupAuthorizationChecked=false;
  const authorizationNoticeKey='monitor.helper-authorization-notice.v1';
  function checkStartupAuthorization(status:CaptureStatus){
    if(startupAuthorizationChecked)return;
    startupAuthorizationChecked=true;
    if(!status.supported||status.installed)return;
    try{if(localStorage.getItem(authorizationNoticeKey)==='seen')return;}catch{}
    if(!document.querySelector('dialog[open]'))authorizationDialog.showModal();
  }
  function dismissAuthorizationNotice(){
    try{localStorage.setItem(authorizationNoticeKey,'seen');}catch{}
    authorizationDialog.close();
  }
  function openHelperSettings(){
    dismissAuthorizationNotice();
    settingsSection='helper';
    settingsDialog.showModal();
  }
  let autostart=$state(false);let generalLoaded=$state(false);let generalBusy=$state(false);let generalError=$state('');
  async function setGeneral(kind:'autostart'|'tray',enabled:boolean){
    generalBusy=true;generalError='';
    try{
      if(kind==='autostart')autostart=await invoke<boolean>('set_autostart',{enabled});
      else config=await invoke<Config>('set_close_to_tray',{enabled});
    }catch(e){generalError=String(e);}finally{generalBusy=false;}
  }
  let settingsSection=$state<'general'|'helper'|'jev'>('general');
  type CaptureStatus={supported:boolean;installed:boolean;phase:string;message:string;packets:{pid:number;agent_id:string;target:string;bytes:number;at_ms:number}[]};
  let captureStatus=$state<CaptureStatus|null>(null);
  const packets=$derived((captureStatus?.packets??[]).filter(p=>p.agent_id===selected));
  let addDialog:HTMLDialogElement;
  let addError=$state('');
  $effect(()=>{if(adding)addDialog?.showModal();else addDialog?.close();});
  const agents=$derived((snapshot?.agents??[]).filter(a=>a.id!=='unclassified'));
  const current=$derived(snapshot?.agents.find(a=>a.id===selected));
  const processes=$derived((snapshot?.processes??[]).filter(p=>p.agent_id===selected));
  const connections=$derived((snapshot?.activities??[]).filter(a=>a.agent_id===selected&&a.kind==='connection').sort((a,b)=>a.pid-b.pid||a.target.localeCompare(b.target)));
  const candidates=$derived([...new Map((snapshot?.processes??[]).filter(p=>p.agent_id==='unclassified'&&p.executable).map(p=>[p.executable,p])).values()]);
  function enabled(a:Agent){return config?.enabled[a.id]??a.enabled;}
  async function toggle(a:Agent){busy=true;error='';try{config=await invoke<Config>('set_agent_monitoring',{id:a.id,enabled:!enabled(a)});}catch(e){error=String(e);}finally{busy=false;}}
  async function choose(){addError='';try{const path=await open({multiple:false,title:$t("选择 Agent 应用或可执行文件")});if(typeof path==='string')executable=path;}catch(e){addError=String(e);}}
  async function add(){busy=true;addError='';try{config=await invoke<Config>('register_agent',{name,executable});adding=false;name='';executable='';}catch(e){addError=String(e);}finally{busy=false;}}
  onMount(()=>{let stopped=false;let timer:ReturnType<typeof setTimeout>;
    let unlistenSettings:(()=>void)|undefined;
    if(isTauri())void getCurrentWindow().listen('monitor-open-settings',()=>{
      if(!stopped&&!settingsDialog.open)settingsDialog.showModal();
    }).then(unlisten=>{if(stopped)unlisten();else unlistenSettings=unlisten;}).catch(e=>{if(!stopped)error=String(e);});
    async function tick(){if(stopped)return;try{if(!isTauri())throw new Error($t("请打开桌面程序，读取当前电脑安装的 Agent。"));const [next,capture]=await Promise.all([invoke<Snapshot>('live_status'),invoke<CaptureStatus>('capture_status')]);if(stopped)return;snapshot=next;captureStatus=capture;checkStartupAuthorization(capture);if(!next.agents.some(a=>a.id===selected))selected='';}catch(e){if(!stopped)error=String(e);}if(!stopped)timer=setTimeout(tick,1000);}
    if(isTauri())void invoke<Config>('monitor_settings').then(c=>{if(!stopped)config=c;}).catch(e=>{error=String(e);});
    if(isTauri())void invoke<boolean>('autostart_enabled').then(value=>{if(!stopped){autostart=value;generalLoaded=true;}}).catch(e=>{if(!stopped)generalError=String(e);});
    void tick();return()=>{stopped=true;clearTimeout(timer);unlistenSettings?.();};
  });
</script>

<DevelopmentPermissions startup />
<div class="shell">
  <aside class="sidebar">
    <div class="brand" data-tauri-drag-region>
      <img class="logo" src="/monitor-icon.png" alt={$t("Monitor 图标")} width="36" height="36" draggable="false" />
      <span class="brand-text">
        <span class="brand-name">Monitor</span>
        <span class="brand-sub">{$t("本机 Agent 监测")}</span>
      </span>
      <button class="settings-btn" aria-haspopup="dialog" aria-label={$t("设置")} title={$t("设置")} onclick={()=>settingsDialog.showModal()}>
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h.01a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51h.01a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v.01a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
      </button>
    </div>
    <nav class="agent-list" aria-label={$t("Agent 列表")}>
      {#each agents as a (a.id)}
        <div class="agent-item" class:selected={selected===a.id}>
          <button class="agent-main" aria-current={selected===a.id?'true':undefined} onclick={()=>{selected=selected===a.id?'':a.id;detail='protection';}}>
            <AgentIcon id={a.id} name={a.name}/>
            <span class="agent-meta">
              <span class="agent-name">{a.name}</span>
              <span class="agent-status"><span class="dot" class:running={a.running>0}></span>{a.running>0?$t('{count} 个进程',{count:a.running}):a.installed?$t("已安装"):a.custom?$t("手动添加"):$t("未运行")}</span>
            </span>
          </button>
          <label class="toggle" title={enabled(a)?$t("监测已开启"):$t("监测已关闭")}>
            <input type="checkbox" role="switch" aria-label={$t('{name} 监测',{name:a.name})} checked={enabled(a)} disabled={busy||!config} onchange={()=>toggle(a)}/>
            <span class="switch" aria-hidden="true"></span>
          </label>
        </div>
      {/each}
      {#if !snapshot?.running && !error}<p class="side-empty" role="status">{$t("正在扫描本机…")}</p>
      {:else if !agents.length && snapshot?.running}<p class="side-empty">{$t("尚未发现 Agent")}</p>{/if}
    </nav>
    <footer class="side-footer"><button class="add-agent-btn" aria-label={$t("添加 Agent")} title={$t("添加 Agent")} aria-haspopup="dialog" onclick={()=>{addError='';adding=true;}}>＋</button></footer>
  </aside>

  <section class="content">
    {#if error}<p class="alert" role="alert">{error}</p>{/if}
    {#if current}
      <header class="content-head">
        <div class="head-title">
          <AgentIcon id={current.id} name={current.name}/>
          <div>
            <h1>{current.name}</h1>
            <p class="muted">{$t('{count} 个进程',{count:processes.length})} · {enabled(current)?$t("监测已开启"):$t("监测已关闭")}</p>
          </div>
        </div>
      </header>
      <div class="tabs" role="tablist">
        <button role="tab" aria-selected={detail==='protection'} class:active={detail==='protection'} onclick={()=>detail='protection'}>{$t('设置')}</button>
        <button role="tab" aria-selected={detail==='processes'} class:active={detail==='processes'} onclick={()=>detail='processes'}>{$t("进程")}</button>
        <button role="tab" aria-selected={detail==='activity'} class:active={detail==='activity'} onclick={()=>detail='activity'}>{$t("活动日志")}</button>
        <button role="tab" aria-selected={detail==='blocks'} class:active={detail==='blocks'} onclick={()=>detail='blocks'}>{$t("拦截日志")}</button>
      </div>
      {#if detail==='processes'}
        {#if processes.length}
          <div class="card table-card"><table><thead><tr><th>{$t("进程")}</th><th>PID</th><th>{$t("程序路径")}</th></tr></thead><tbody>
            {#each processes as p}<tr><td>{p.name}</td><td>{p.pid}</td><td class="mono path-cell">{p.executable||$t("路径不可读取")}</td></tr>{/each}
          </tbody></table></div>
        {:else}<div class="card empty">{$t("当前未发现该 Agent 的运行进程。")}</div>{/if}
      {:else if detail==='activity'}
        <div class="card table-card"><table class="live-connections" aria-label={$t("实时网络活动（约每三秒采样）")}><thead><tr><th>PID</th><th>{$t("网络连接地址")}</th><th>{$t("包大小")}</th></tr></thead><tbody>
          {#if !enabled(current)}
            <tr><td colspan="3" class="empty">{$t("监测已关闭")}</td></tr>
          {:else if !snapshot?.running}
            <tr><td colspan="3" class="empty">{$t("等待实时采集…")}</td></tr>
          {:else if packets.length}
            {#each packets as packet}<tr><td class="mono">{packet.pid}</td><td class="mono connection-address">{packet.target}</td><td title={$t('采集时间 {time} · 单个 IP 包长度（含 IP 头），不是累计流量',{time:new Date(packet.at_ms).toLocaleTimeString($language)})}>{packet.bytes} B</td></tr>{/each}
          {:else}
            {#each connections as connection (`${connection.pid}:${connection.target}`)}
              <tr><td class="mono">{connection.pid}</td><td class="mono connection-address">{connection.target}</td><td class="muted" title={$t("连接采样不包含包长度；已启用抓包时，等待此连接发出新数据包")}>{captureStatus?.phase==='running'?$t("等待数据包"):$t("未采集")}</td></tr>
            {:else}<tr><td colspan="3" class="empty">{$t("本轮未采集到网络连接")}</td></tr>{/each}
          {/if}
        </tbody></table></div>
      {:else if detail==='protection'}
        {#key selected}<ProtectionSettings agentId={selected}/>{/key}
      {:else}
        {#key selected+detail}<AuditLog agentId={selected} initialBlocked={detail==='blocks'} fixedType={true}/>{/key}
      {/if}
    {:else}
      <div class="placeholder">
        <h1>{$t("这台电脑上的 Agent")}</h1>
        <p class="muted">{$t("从左侧选择一个 Agent 查看进程与活动日志。")}</p>
      </div>
    {/if}
  </section>
</div>

<dialog class="add-dialog" bind:this={authorizationDialog} aria-labelledby="authorization-title" oncancel={(event)=>{event.preventDefault();dismissAuthorizationNotice();}}>
  <div class="add-form">
    <h2 id="authorization-title">{$t("授权安装辅助服务")}</h2>
    <p class="authorization-note">{$t("Monitor 尚未安装辅助服务。采集 Agent 的数据包大小需要安装服务，并完成 macOS 管理员授权；安装后会自动监测所有已开启的 Agent。")}</p>
    <p class="authorization-note">{$t("如果暂不安装，可继续查看进程和网络连接。之后请前往「设置 → 辅助服务」，点击「安装」完成授权。")}</p>
    <div class="dialog-actions"><button onclick={dismissAuthorizationNotice}>{$t("暂不安装")}</button><button class="primary" onclick={openHelperSettings}>{$t("前往设置")}</button></div>
  </div>
</dialog>

<dialog class="settings-dialog" bind:this={settingsDialog} aria-labelledby="settings-title">
  <div class="settings-layout">
    <nav class="settings-nav" aria-label={$t("设置菜单")}>
      <h2 id="settings-title">{$t("设置")}</h2>
      <button class:active={settingsSection==='general'} aria-current={settingsSection==='general'?'page':undefined} onclick={()=>settingsSection='general'}>{$t("通用设置")}</button>
      <button class:active={settingsSection==='helper'} aria-current={settingsSection==='helper'?'page':undefined} onclick={()=>settingsSection='helper'}>{$t("辅助服务")}</button>
      <button class:active={settingsSection==='jev'} aria-current={settingsSection==='jev'?'page':undefined} onclick={()=>settingsSection='jev'}>{$t('Jev 模型')}</button>
    </nav>
    <section class="settings-content" aria-labelledby="settings-section-title">
      <header class="settings-header">
        <h3 id="settings-section-title">{settingsSection==='general'?$t("通用设置"):settingsSection==='helper'?$t("辅助服务"):$t('Jev 模型')}</h3>
        <button class="settings-close" aria-label={$t("关闭设置")} title={$t("关闭")} onclick={()=>settingsDialog.close()}><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18"/></svg></button>
      </header>
      {#if settingsSection==='general'}
        <label class="preference-row"><span>{$t('语言设置')}</span><select bind:value={$language}><option value="zh-CN">简体中文</option><option value="en">English</option></select></label>
        <label class="preference-row"><span>{$t('主题设置')}</span><select bind:value={$theme}><option value="light">{$t('浅色主题')}</option><option value="dark">{$t('深色主题')}</option><option value="system">{$t('跟随系统')}</option></select></label>
        <div class="preference-row"><span>{$t('开机启动')}</span><label class="toggle"><input type="checkbox" role="switch" aria-label={$t('开机启动')} checked={autostart} disabled={!generalLoaded||generalBusy} onchange={(e)=>{const enabled=e.currentTarget.checked;e.currentTarget.checked=autostart;void setGeneral('autostart',enabled);}}/><span class="switch" aria-hidden="true"></span></label></div>
        <div class="preference-row"><span>{$t('关闭窗口时最小化到托盘')}</span><label class="toggle"><input type="checkbox" role="switch" aria-label={$t('关闭窗口时最小化到托盘')} checked={config?.close_to_tray??false} disabled={!config||generalBusy} onchange={(e)=>{const enabled=e.currentTarget.checked;e.currentTarget.checked=config?.close_to_tray??false;void setGeneral('tray',enabled);}}/><span class="switch" aria-hidden="true"></span></label></div>
        {#if generalError}<p class="alert" role="alert">{generalError}</p>{/if}
      {:else if settingsSection==='jev'}
        <JevSettings/>
      {:else}
        <PacketCapture status={captureStatus} titleId="settings-capture-title"/>
        <SystemExtensionStatus/>
      {/if}
    </section>
  </div>
</dialog>

<dialog class="add-dialog" bind:this={addDialog} aria-labelledby="add-agent-title" onclose={()=>adding=false} oncancel={(event)=>{if(busy)event.preventDefault();else adding=false;}}>
  <form class="add-form" onsubmit={(event)=>{event.preventDefault();void add();}}>
    <h2 id="add-agent-title">{$t("添加 Agent")}</h2>
    <label>{$t("名称")}<input aria-label={$t("Agent 名称")} placeholder={$t("Agent 名称")} bind:value={name} required disabled={busy}/></label>
    <label>{$t("程序路径")}<div class="add-row"><input aria-label={$t("Agent 程序路径")} placeholder={$t("应用或可执行文件")} bind:value={executable} required disabled={busy}/><button type="button" disabled={busy} onclick={choose}>{$t("浏览")}</button></div></label>
    <label>{$t("从运行中的程序选择")}<select disabled={busy} aria-label={$t("从运行进程选择")} onchange={(e)=>{executable=e.currentTarget.value;const p=candidates.find(p=>p.executable===executable);if(p&&!name)name=p.name;}}>
      <option value="">{$t("选择一个运行中的程序")}</option>
      {#each candidates as p}<option value={p.executable}>{p.name} · {p.executable}</option>{/each}
    </select></label>
    {#if addError}<p class="alert" role="alert">{addError}</p>{/if}
    <div class="dialog-actions"><button type="button" disabled={busy} onclick={()=>adding=false}>{$t("取消")}</button><button type="submit" class="primary" disabled={busy||!name.trim()||!executable.trim()}>{busy?$t("正在添加…"):$t("添加并开启监测")}</button></div>
  </form>
</dialog>

<style>
  .shell{display:grid;grid-template-columns:296px 1fr;height:100%;overflow:hidden}
  .sidebar{display:flex;flex-direction:column;border-right:1px solid var(--border);background:var(--surface);height:100%;min-height:0;padding-top:38px;overflow:hidden}
  .brand{display:flex;align-items:center;gap:11px;padding:12px 16px 14px;margin-bottom:12px;border-bottom:1px solid var(--border);-webkit-user-select:none;user-select:none}
  .logo{display:block;width:36px;height:36px;object-fit:contain;flex-shrink:0;pointer-events:none;border-radius:9px;border:1px solid var(--border);box-shadow:0 1px 3px rgba(0,0,0,.08)}
  .brand-text{display:flex;flex-direction:column;min-width:0;line-height:1.3}
  .brand-name{font-weight:650;font-size:14px;letter-spacing:-.2px}
  .brand-sub{font-size:11px;color:var(--text-3);margin-top:1px}
  .brand-text{flex:1}
  .settings-btn{display:grid;place-items:center;width:28px;height:28px;padding:0;flex-shrink:0;border:1px solid transparent;background:none;color:var(--text-3);border-radius:var(--radius-sm)}
  .settings-btn:hover{background:var(--surface-hover);color:var(--text);border-color:var(--border)}
  .settings-dialog{width:min(680px,calc(100vw - 32px));max-height:calc(100dvh - 48px);padding:0;overflow:auto;border:1px solid var(--border);border-radius:14px;background:var(--surface);color:var(--text);box-shadow:0 20px 70px #0003;backdrop-filter:blur(24px)}
  .settings-dialog::backdrop{background:#0005;backdrop-filter:blur(4px)}
  .settings-layout{display:grid;grid-template-columns:156px minmax(0,1fr);min-height:360px}
  .settings-nav{display:flex;flex-direction:column;gap:6px;padding:24px 12px;border-right:1px solid var(--border);background:var(--bg)}
  .settings-nav h2{font-size:16px;margin:0 10px 18px}
  .settings-nav button{text-align:left;border:1px solid transparent;background:transparent;padding:10px 12px;border-radius:var(--radius-sm);color:var(--text-2)}
  .settings-nav button.active{background:var(--surface-hover);border-color:var(--border);color:var(--text);font-weight:600}
  .settings-content{padding:24px;min-width:0;overflow-wrap:anywhere}
  .settings-header{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:28px}
  .settings-header h3{margin:0;font-size:16px}
  .settings-close{display:grid;place-items:center;width:28px;height:28px;flex-shrink:0;padding:0;line-height:1;background:transparent;border-color:transparent;color:var(--text-2)}
  .settings-close svg{display:block}
  .authorization-note{margin:0;font-size:13px;line-height:1.8;color:var(--text-2)}
  .preference-row{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:22px;font-size:13px}.preference-row select{min-width:140px}
  .add-dialog{width:min(460px,calc(100vw - 32px));max-height:calc(100dvh - 48px);overflow:auto;padding:24px;border:1px solid var(--border);border-radius:14px;background:var(--surface);color:var(--text);box-shadow:0 20px 70px #0003}
  .add-dialog::backdrop{background:#0005;backdrop-filter:blur(4px)}
  .add-form{display:flex;flex-direction:column;gap:18px}
  .add-form h2{margin:0;font-size:18px}
  .add-form label{display:flex;flex-direction:column;gap:7px;font-size:12px;color:var(--text-2)}
  .dialog-actions{display:flex;justify-content:flex-end;gap:10px;margin-top:4px}
  .add-row{display:flex;gap:8px}.add-row input{flex:1}
  .agent-list{flex:1;overflow-y:auto;padding:0 8px 8px;min-height:0}
  .agent-item{display:flex;align-items:center;gap:4px;border-radius:var(--radius-sm);padding:2px 6px 2px 2px}
  .agent-item:hover{background:var(--surface-hover)}
  .agent-item.selected{background:var(--surface-hover)}
  .agent-main{display:flex;align-items:center;gap:10px;flex:1;min-width:0;background:none;border:0;padding:6px 8px;text-align:left;border-radius:var(--radius-sm)}
  .agent-main:hover:not(:disabled){background:none}
  .agent-meta{display:flex;flex-direction:column;min-width:0}
  .agent-name{font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .agent-status{font-size:11px;color:var(--text-2);display:flex;align-items:center;gap:5px;margin-top:1px}
  .dot{width:6px;height:6px;border-radius:50%;background:var(--text-3);flex-shrink:0}
  .dot.running{background:var(--green)}
  .toggle{position:relative;flex-shrink:0;cursor:pointer}
  .toggle input{position:absolute;inset:0;opacity:0;margin:0;cursor:pointer;width:100%;height:100%}
  .switch{position:relative;display:block;flex-shrink:0;width:30px;height:18px;border-radius:99px;background:var(--border-strong);transition:background .15s;pointer-events:none}
  .switch:after{content:'';position:absolute;top:50%;left:2px;width:14px;height:14px;border-radius:50%;background:#fff;transform:translateY(-50%);box-shadow:0 1px 2px rgba(0,0,0,.2);transition:transform .15s}
  .toggle input:checked+.switch{background:var(--green)}
  .toggle input:checked+.switch:after{transform:translate(12px,-50%)}
  .toggle input:focus-visible+.switch{outline:2px solid var(--text);outline-offset:2px}
  .side-empty{padding:18px 12px;color:var(--text-3);font-size:12px;text-align:center}
  .side-footer{display:flex;flex-shrink:0;border-top:1px solid var(--border)}
  .add-agent-btn{display:block;width:100%;min-height:48px;border:0;border-radius:0;padding:14px 16px;background:transparent}
  .add-agent-btn:focus-visible{outline-offset:-3px}
  .content{overflow-y:auto;padding:62px 32px 48px;min-width:0;min-height:0}
  .alert{background:var(--surface);border:1px solid var(--red);color:var(--red);border-radius:var(--radius-sm);padding:10px 14px;margin:0 0 16px}
  .content-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:6px}
  .head-title{display:flex;align-items:center;gap:12px}
  .head-title h1{font-size:17px;font-weight:600;letter-spacing:-.2px;margin:0}
  .head-title p{margin:2px 0 0;font-size:12px}
  .path-cell{overflow-wrap:anywhere;color:var(--text-2)}
  .tabs{display:flex;gap:2px;border-bottom:1px solid var(--border);margin:16px 0 20px}
  .tabs button{border:0;background:none;border-radius:0;padding:8px 12px;color:var(--text-2);border-bottom:2px solid transparent;margin-bottom:-1px}
  .tabs button:hover:not(:disabled){background:none;color:var(--text)}
  .tabs button.active{color:var(--text);border-bottom-color:var(--text);font-weight:500}
  .table-card{overflow-x:auto}
  table{width:100%;border-collapse:collapse;font-size:12px}
  th:nth-child(-n+2),td:nth-child(-n+2){white-space:nowrap;width:1%}
  th:last-child{white-space:nowrap}
  .live-connections th:nth-child(2),.live-connections td.connection-address{width:auto;white-space:normal;overflow-wrap:anywhere}
  .live-connections td.empty{white-space:normal;width:auto}
  td.path-cell{white-space:normal;overflow-wrap:anywhere;min-width:100px}
  th{text-align:left;font-weight:500;color:var(--text-2);padding:10px 14px;border-bottom:1px solid var(--border);background:var(--bg)}
  td{padding:10px 14px;border-bottom:1px solid var(--border);vertical-align:top}
  tr:last-child td{border-bottom:0}
  .empty{padding:32px;text-align:center;color:var(--text-3)}
  .placeholder{max-width:420px;margin:18vh auto 0;text-align:center}
  .placeholder h1{font-size:20px;font-weight:600;letter-spacing:-.3px;margin:0 0 8px}
  @media(max-width:760px){
    .shell{grid-template-columns:220px minmax(0,1fr)}
    .content{padding:54px 16px 16px}
  }
  @media(prefers-reduced-motion:reduce){.switch,.switch:after,button{transition:none}}
</style>
