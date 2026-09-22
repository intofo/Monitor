<script lang="ts">
  import { onMount } from 'svelte';
  import { invoke, isTauri } from '@tauri-apps/api/core';
  import { t } from './preferences';
  let {startup=false}:{startup?:boolean}=$props();
  type Status={supported:boolean;host_signed:boolean;sip:'enabled'|'disabled'|'unknown'};
  let status=$state<Status|null>(null);let error=$state('');let busy=$state(false);
  let dialog:HTMLDialogElement;
  const noticeKey='monitor.development-permissions.v1';
  async function refresh(){busy=true;error='';try{status=await invoke<Status>('system_extension_status');}catch(e){error=String(e);}finally{busy=false;}}
  function dismiss(){try{localStorage.setItem(noticeKey,'seen');}catch{}dialog.close();}
  onMount(()=>{let stopped=false;let timer:ReturnType<typeof setTimeout>;
    if(isTauri())void refresh().then(()=>{
      if(stopped||!startup||!status?.supported||status.host_signed)return;
      try{if(localStorage.getItem(noticeKey)==='seen')return;}catch{}
      function show(){if(stopped)return;if(document.querySelector('dialog[open]')){timer=setTimeout(show,500);return;}dialog.showModal();}
      show();
    });
    return()=>{stopped=true;clearTimeout(timer);};
  });
</script>
{#if !startup&&status?.supported&&!status.host_signed}
  <button class="dev-note" onclick={()=>{dialog.showModal();void refresh();}}>{$t('开发版权限说明')}</button>
{/if}
<dialog bind:this={dialog} aria-labelledby={startup?'startup-dev-title':'settings-dev-title'} oncancel={(event)=>{event.preventDefault();dismiss();}}>
  <h2 id={startup?'startup-dev-title':'settings-dev-title'}>{$t('开发版权限说明')}</h2>
  <p>{$t('当前为未正式签名版本。普通监测不需要关闭 SIP；测试系统拦截扩展可使用开发模式。')}</p>
  <p class="status">SIP：{status?.sip==='enabled'?$t('已开启'):status?.sip==='disabled'?$t('已关闭'):$t('无法确认，请运行 csrutil status 检查')}</p>
  <p>{$t('关闭 SIP 会降低整台电脑的系统保护，仅建议在开发测试机上临时使用。Monitor 不会自动关闭 SIP。')}</p>
  {#if status?.sip!=='disabled'}
    <ol>
      <li>{$t('进入 macOS 恢复模式：Apple 芯片机型关机后长按电源键，选择「选项」；Intel 机型重启时按住 Command + R。')}</li>
      <li>{$t('在「实用工具 → 终端」运行以下命令，然后重新启动：')}<code>csrutil disable</code></li>
    </ol>
  {/if}
  <p>{$t('回到系统后，可在终端启用系统扩展开发模式：')}<code>systemextensionsctl developer on</code></p>
  <p>{$t('仍需带 entitlement 的本地签名、正确打包扩展，以及系统批准和完全磁盘访问权限。关闭 SIP 不代表拦截已生效。')}</p>
  <p>{$t('测试结束后，在恢复模式终端运行 csrutil enable 并重启；回到系统运行 systemextensionsctl developer off。')}</p>
  {#if error}<p role="alert">{error}</p>{/if}
  <div class="actions"><button disabled={busy} onclick={refresh}>{$t('重新检测')}</button><button class="primary" onclick={dismiss}>{$t('暂不配置，继续使用')}</button></div>
</dialog>
<style>
  .dev-note{padding:3px 9px;font-size:11px;border-color:var(--border);color:var(--text-2)}
  dialog{width:min(580px,calc(100vw - 32px));max-height:calc(100dvh - 48px);overflow:auto;padding:24px;border:1px solid var(--border);border-radius:14px;background:color-mix(in srgb,var(--surface) 94%,transparent);color:var(--text);backdrop-filter:blur(24px);box-shadow:0 20px 70px #0003}dialog::backdrop{background:#0005;backdrop-filter:blur(4px)}h2{margin:0 0 12px;font-size:18px}p,li{font-size:13px;color:var(--text-2)}li{margin-bottom:10px}code{display:block;margin:8px 0;padding:8px 12px;background:var(--bg);border-radius:8px;user-select:text}.status{color:var(--text)}.actions{display:flex;justify-content:flex-end;gap:10px;margin-top:20px}
</style>
