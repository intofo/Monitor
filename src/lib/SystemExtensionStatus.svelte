<script lang="ts">
  import { onMount } from 'svelte';
  import { invoke } from '@tauri-apps/api/core';
  import DevelopmentPermissions from './DevelopmentPermissions.svelte';
  import { t } from './preferences';
  type Component={identifier:string;bundled:boolean;signed:boolean;local_signed:boolean;entitled:boolean;activation:string;error:string};
  type Status={supported?:boolean;host_signed:boolean;sip:string;host_entitled:boolean;endpoint:Component;network:Component};
  let status=$state<Status|null>(null);let error=$state('');let busy=$state(false);
  onMount(()=>{let stopped=false;let timer:ReturnType<typeof setTimeout>;
    async function poll(){try{const value=await invoke<Status>('system_extension_status');if(!stopped)status=value;}catch(e){if(!stopped)error=String(e);}if(!stopped)timer=setTimeout(poll,2000);}
    void poll();return()=>{stopped=true;clearTimeout(timer);};
  });
  function tone(component:Component){
    if(component.error||component.activation==='failed')return 'bad';
    if(component.activation==='activated'||((component.signed||(status?.sip==='disabled'&&component.local_signed))&&component.entitled&&component.activation===''))return 'ok';
    return 'warn';
  }
  function label(component:Component){
    if(!component.bundled)return $t('尚未打包');
    if((!component.signed&&!(status?.sip==='disabled'&&component.local_signed))||!component.entitled)return $t('待签名授权');
    return $t(({activating:'正在激活…',approval_required:'等待系统批准',activated:'已激活，等待执行器连接',restart_required:'需要重启系统',failed:'激活失败'} as Record<string,string>)[component.activation]??'可请求激活');
  }
  async function setNetwork(enabled:boolean){busy=true;error='';try{await invoke('set_network_filter',{enabled});}catch(e){error=String(e);}finally{busy=false;}}
  async function activate(kind:string){busy=true;error='';try{await invoke('activate_system_extension',{kind});}catch(e){error=String(e);}finally{busy=false;}}
</script>
<div class="extensions">
  <div class="block-head">
    <h4>{$t('系统拦截组件')}</h4>
    <DevelopmentPermissions />
  </div>
  {#if status?.supported===false}<p class="hint">{$t('系统扩展仅支持 macOS。')}</p>
  {:else if status}
    {#each [{kind:'endpoint',name:$t('文件访问拦截'),component:status.endpoint},{kind:'network',name:$t('网络连接拦截'),component:status.network}] as entry}
      <div class="extension-row">
        <div class="extension-info">
          <span class="extension-name">{entry.name}</span>
          <span class="pill" class:ok={tone(entry.component)==='ok'} class:warn={tone(entry.component)==='warn'} class:bad={tone(entry.component)==='bad'}>{label(entry.component)}</span>
        </div>
        {#if entry.component.bundled&&(entry.component.signed||(status.sip==='disabled'&&entry.component.local_signed))&&entry.component.entitled&&status.host_entitled}
          <button disabled={busy||['activating','approval_required','restart_required','activated'].includes(entry.component.activation)} onclick={()=>activate(entry.kind)}>{$t('请求激活')}</button>
        {/if}
      </div>
      {#if entry.kind==='network'&&entry.component.activation==='activated'}
        <div class="extension-row network-actions"><button disabled={busy} onclick={()=>setNetwork(true)}>{$t('启用网络过滤')}</button><button disabled={busy} onclick={()=>setNetwork(false)}>{$t('停用网络过滤')}</button></div>
      {/if}
      {#if entry.component.error}<p class="error" role="alert">{entry.component.error}</p>{/if}
    {/each}
  {:else}<p class="hint">{$t('正在读取…')}</p>{/if}
  {#if error}<p class="error" role="alert">{error}</p>{/if}
</div>
<style>
.extensions{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow);padding:16px;margin:0 0 16px}
.block-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:6px}
h4{margin:0;font-size:13px;font-weight:600;letter-spacing:-.1px}
.extension-row{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:10px 0;border-top:1px solid var(--border);font-size:13px}
.extension-info{display:flex;flex-direction:column;align-items:flex-start;gap:6px;min-width:0}
.extension-name{font-weight:500}
.network-actions{justify-content:flex-end;gap:8px;padding-top:0;border-top:0}
.hint{margin:0;font-size:12px;color:var(--text-2)}
.error{margin:8px 0 0;font-size:12px;line-height:1.6;color:var(--red);overflow-wrap:anywhere}
</style>
