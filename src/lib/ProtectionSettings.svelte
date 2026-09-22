<script lang="ts">
  import Toast from './Toast.svelte';
  import { onMount } from 'svelte';
  import { invoke } from '@tauri-apps/api/core';
  import { open } from '@tauri-apps/plugin-dialog';
  import { t } from './preferences';
  let {agentId}:{agentId:string}=$props();
  type Mode='observe'|'allowlist'|'ask'|'offline'|'ai';
  type Grant={host:string;port:number;transport:'tcp'|'udp'};
  type Policy={mode:Mode;project_directories:string[];readable_directories:string[];network_allowlist:Grant[];model_api_allowlist:Grant[];allow_web:boolean};
  type Settings={policy:Policy;enforcement_available:boolean;ai_approved:boolean};
  let policy=$state<Policy>({mode:'observe',project_directories:[],readable_directories:[],network_allowlist:[],model_api_allowlist:[],allow_web:false});
  let ready=$state(false);let busy=$state(false);let error=$state('');let saved=$state(false);
  type Candidate={origin:string;source:string;grant:Grant};
  let candidates=$state<Candidate[]>([]);let approvedOrigins=$state<string[]>([]);let approvalToken=$state('');let unreadable=$state<string[]>([]);let aiApproved=$state(false);let reviewMessage=$state('');let jevEndpoint=$state('');
  let approvalDialog:HTMLDialogElement;
  let whitelistDialog:HTMLDialogElement;
  async function prepareApproval(){
    busy=true;error='';
    try{const result=await invoke<{token:string;discovery:{candidates:Candidate[];unreadable:string[]}}>('discover_model_apis',{agentId,policy});approvalToken=result.token;candidates=result.discovery.candidates;unreadable=result.discovery.unreadable;approvedOrigins=candidates.map(c=>c.origin);approvalDialog.showModal();}catch(e){error=String(e);}finally{busy=false;}
  }
  async function testAi(){busy=true;error='';try{const result=await invoke<{decision:string;reason:string}>('test_agent_ai_review',{agentId});reviewMessage=`${result.decision}: ${result.reason}`;}catch(e){error=String(e);}finally{busy=false;}}
  let host=$state('');let port=$state(443);let transport=$state<'tcp'|'udp'>('tcp');
  const modes=$derived([
    {id:'observe',name:$t('仅监测'),description:$t('记录实时活动，不阻止文件读取或网络连接。')},
    {id:'allowlist',name:$t('白名单拦截'),description:$t('只允许读取指定目录、连接白名单目标，其余请求拒绝。')},
    {id:'ask',name:$t('访问时询问'),description:$t('白名单之外的访问需确认；未获批准前拒绝，超时默认拒绝。')},
    {id:'offline',name:$t('禁止联网'),description:$t('允许已批准的模型 API 和单独开启的网页连接，其余网络连接拒绝。')},
    {id:'ai',name:$t('AI 拦截'),description:$t('使用 Jev 辅助审查异常访问；判断失败或等待判断时维持拒绝。')}
  ]);
  onMount(()=>{let disposed=false;void invoke<Settings>('protection_settings',{agentId}).then(result=>{if(!disposed){policy=result.policy;aiApproved=result.ai_approved;ready=true;}}).catch(e=>{if(!disposed)error=String(e);});const timer=setInterval(()=>{if(!ready||busy)return;void invoke<Settings>('protection_settings',{agentId}).then(result=>{if(!disposed)policy.project_directories=result.policy.project_directories;}).catch(()=>{});},3000);return()=>{disposed=true;clearInterval(timer);};});
  async function chooseDirectory(kind:'readable_directories'){
    error='';busy=true;
    try{const paths=await open({directory:true,multiple:true,title:$t('选择允许读取的目录')});if(paths){policy[kind]=[...new Set([...policy[kind],...(Array.isArray(paths)?paths:[paths])])];saved=false;}}
    catch(e){error=String(e);}finally{busy=false;}
  }
  function addTarget(){
    if(!host.trim()||!Number.isInteger(port)||port<1||port>65535)return;
    if(!policy.network_allowlist.some(g=>g.host===host.trim()&&g.port===port&&g.transport===transport))policy.network_allowlist=[...policy.network_allowlist,{host:host.trim(),port,transport}];
    host='';saved=false;
  }
  async function save(approved=false){
    if(!approved&&policy.mode==='offline'){await prepareApproval();return;}
    if(!approved&&policy.mode==='ai'){busy=true;error='';try{const jev=await invoke<{settings:{api_url:string}}>('jev_settings');jevEndpoint=jev.settings.api_url;approvalDialog.showModal();}catch(e){error=String(e);}finally{busy=false;}return;}
    busy=true;error='';saved=false;reviewMessage='';
    try{const result=await invoke<Settings>('save_protection_settings',{agentId,policy,approvalToken:policy.mode==='offline'?approvalToken:null,approvedOrigins:policy.mode==='offline'?approvedOrigins:[],aiApproved:policy.mode==='ai'&&approved,approvedAiEndpoint:policy.mode==='ai'?jevEndpoint:null});policy=result.policy;aiApproved=result.ai_approved;saved=true;}
    catch(e){error=String(e);}finally{busy=false;}
  }
  function approve(){approvalDialog.close();void save(true);}

</script>
<div class="protection-settings">
  <p class="capability" role="status">{$t('系统拦截组件尚未接入，以下设置仅保存规则，尚未生效。')}</p>
  <fieldset disabled={!ready||busy}>
    <div class="mode-heading"><h4>{$t('拦截模式')}</h4><button onclick={()=>whitelistDialog.showModal()}>{$t('白名单设置')}</button></div>
    <div class="mode-list">
      {#each modes as mode}<label class="mode" class:selected={policy.mode===mode.id}>
        <input type="radio" name="protection-mode" value={mode.id} bind:group={policy.mode} onchange={()=>saved=false}/>
        <span><strong>{mode.name}</strong><small>{mode.description}</small></span>
      </label>{/each}
    </div>
    {#if policy.mode==='offline'}
      <p class="note">{$t('保存前读取模型 API 候选地址，逐项批准后才加入该 Agent 的白名单。网页连接权限单独设置。')}</p>
      {#each policy.model_api_allowlist as grant}<p class="note mono">{grant.host}:{grant.port} / {grant.transport.toUpperCase()}</p>{/each}
    {/if}
    {#if policy.mode==='ai'}
      <p class="note">{$t('先在设置中配置 Jev。只发送事件摘要，不发送源码、文件内容或 Agent 密钥；模型判断不是上传证据。')}</p>
      {#if aiApproved}<button onclick={testAi}>{$t('模拟越界读取，测试 AI')}</button>{/if}
      {#if reviewMessage}<Toast message={reviewMessage}/>{/if}
    {/if}
    <div class="save-row"><button class="primary" onclick={()=>save()}>{busy?$t('保存中…'):$t('保存规则')}</button></div>
  </fieldset>
  {#if saved}<Toast message={$t('规则已保存，系统拦截尚未生效。')}/>{/if}
  {#if error}<Toast message={error} error/>{/if}
</div>
<dialog bind:this={whitelistDialog} aria-labelledby="whitelist-title">
  <h3 id="whitelist-title">{$t('白名单设置')}</h3>
  <fieldset disabled={!ready||busy}>
  <label class="web-access"><input type="checkbox" bind:checked={policy.allow_web} onchange={()=>saved=false}/>{$t('允许搜索和访问网页（HTTP/HTTPS）')}</label>
  <p class="note">{$t('此选项允许公开网站连接，无法区分加密连接中的网页读取与上传。')}</p>
      <div class="rule-heading"><h4>{$t('额外可读取目录')}</h4><button onclick={()=>chooseDirectory('readable_directories')}>{$t('添加目录')}</button></div>
      <p class="note">{$t('仅添加 Agent 必需的运行库或配置目录，避免授权整个用户目录。')}</p>
      {#each policy.readable_directories as path}<div class="rule"><span class="mono">{path}</span><button aria-label={`${$t('移除')} ${path}`} onclick={()=>{policy.readable_directories=policy.readable_directories.filter(p=>p!==path);saved=false;}}>{$t('移除')}</button></div>{/each}
      {#if policy.mode!=='offline'}
        <h4>{$t('网络白名单')}</h4>
        <p class="note">{$t('按精确域名或 IP、端口和协议授权；允许联网不代表能识别或阻止该连接内的源码上传。')}</p>
        <div class="network-fields">
          <label>{$t('域名或 IP')}<input bind:value={host} placeholder="api.example.com"/></label>
          <label>{$t('端口')}<input type="number" min="1" max="65535" step="1" bind:value={port}/></label>
          <label>{$t('协议')}<select bind:value={transport}><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>
        </div>
        <button disabled={!host.trim()||!Number.isInteger(port)||port<1||port>65535} onclick={addTarget}>{$t('添加目标')}</button>
        {#each policy.network_allowlist as grant,index}<div class="rule"><span class="mono">{grant.host}:{grant.port} / {grant.transport.toUpperCase()}</span><button onclick={()=>{policy.network_allowlist=policy.network_allowlist.filter((_,i)=>i!==index);saved=false;}}>{$t('移除')}</button></div>{/each}
      {/if}

    {#if policy.mode==='offline'}<p class="note">{$t('禁止联网模式仅允许批准的模型 API，以及单独开启的网页连接。')}</p>{/if}
    <div class="save-row"><button onclick={()=>whitelistDialog.close()}>{$t('完成')}</button></div>
  </fieldset>
  <p class="note">{$t('关闭后点击保存规则。')}</p>
</dialog>
<dialog bind:this={approvalDialog} aria-labelledby="policy-approval-title">
  <h3 id="policy-approval-title">{policy.mode==='ai'?$t('批准 AI 审查'):$t('批准模型 API 放行')}</h3>
  {#if policy.mode==='ai'}
    <p class="mono">{jevEndpoint}</p>
    <p>{$t('允许 Monitor 将此 Agent 的访问类型、是否在项目内及目标是否已授权等摘要发送给已配置的 Jev。不会发送源码或 Agent 配置中的密钥。')}</p>
  {:else}
    <p>{$t('仅批准以下选中的 API 域名和端口。域名放行也会允许同一站点的其它路径，不能区分加密请求中的代码上传。')}</p>
    {#each candidates as candidate}<label class="candidate"><input type="checkbox" bind:group={approvedOrigins} value={candidate.origin}/><span>{candidate.origin}<small class="mono">{candidate.source}</small></span></label>{/each}
    {#if !candidates.length}<p>{policy.allow_web?$t('未发现模型 API 地址；保留已选择的网页访问权限。'):$t('未发现模型 API 地址，批准后将拒绝全部联网。')}</p>{/if}
    {#if unreadable.length}<p>{$t('部分 Agent 配置未能读取，请检查文件权限。')}</p>{/if}
  {/if}
  <div class="save-row"><button onclick={()=>approvalDialog.close()}>{$t('取消')}</button><button class="primary" onclick={approve}>{$t('批准并保存')}</button></div>
</dialog>
<style>
.web-access{display:flex;align-items:center;gap:10px;font-size:12px;margin:16px 0}
.capability{margin:0 0 20px;padding:12px;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg);color:var(--amber);font-size:12px;line-height:1.7}
dialog{width:min(520px,calc(100vw - 32px));max-height:calc(100dvh - 48px);overflow:auto;padding:24px;border:1px solid var(--border);border-radius:14px;background:var(--surface);color:var(--text)}dialog::backdrop{background:#0005;backdrop-filter:blur(4px)}dialog h3{margin:0 0 16px;font-size:16px}dialog p{font-size:12px;line-height:1.8;color:var(--text-2)}.candidate{display:flex;gap:10px;align-items:flex-start;margin:12px 0;font-size:12px;overflow-wrap:anywhere}.candidate small{display:block;color:var(--text-3);font-size:10px}.save-row{gap:10px}

.mode-heading{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px}.mode-heading h4{margin:0}fieldset{border:0;padding:0;margin:0;min-width:0}h4{font-size:13px;font-weight:600;margin:0 0 10px}.mode-list{display:grid;gap:8px}.mode{display:flex;align-items:flex-start;gap:10px;padding:12px;border:1px solid var(--border);border-radius:var(--radius);cursor:pointer}.mode.selected{background:var(--surface-hover);border-color:var(--border-strong)}.mode input{margin:3px 0 0;accent-color:var(--text);flex-shrink:0}.mode strong{display:block;font-size:13px}.mode small,.note{display:block;color:var(--text-2);font-size:12px;line-height:1.7}.mode small{margin-top:4px}.rule-heading{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:22px}.rule-heading h4{margin:0}.rule{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:10px 0;border-bottom:1px solid var(--border)}.rule span{overflow-wrap:anywhere;min-width:0}.rule button{font-size:11px;flex-shrink:0}.network-fields{display:grid;grid-template-columns:minmax(0,1fr) 74px 86px;gap:8px;margin-bottom:10px}.network-fields label{display:flex;flex-direction:column;gap:6px;font-size:12px}.network-fields input,.network-fields select{width:100%}.save-row{display:flex;justify-content:flex-end;margin-top:24px}h4{margin-top:18px}
</style>
