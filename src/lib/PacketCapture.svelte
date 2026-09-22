<script lang="ts">
  import { t, language } from './preferences';
  import { invoke } from '@tauri-apps/api/core';
  let {status,titleId='capture-title'}:{titleId?:string;status:{supported:boolean;installed:boolean;phase:string;message:string}|null}=$props();
  let busy=$state(false);let error=$state('');let mode=$state<'install'|'remove'>('install');
  let dialog:HTMLDialogElement;
  const pending=$derived(busy||['authorizing','stopping','removing'].includes(status?.phase??''));
  function confirm(action:'install'|'remove'){mode=action;dialog.showModal();}
  async function command(name:string){
    if(pending)return;
    busy=true;error='';
    try{await invoke(name);}catch(e){error=String(e);}finally{busy=false;}
  }
  function submit(){dialog.close();void command(mode==='install'?'install_capture':'uninstall_capture');}
</script>
<div class="capture-permission card-block">
  <div class="block-head">
    <h4>{$t("抓包辅助服务")}</h4>
    <span class="pill" class:ok={status?.installed} class:warn={status&&!status.installed}>{status?(status.installed?$t("已安装"):$t("未安装")):$t("正在读取…")}</span>
  </div>
  <p class="block-desc">{$t("安装后自动采集所有已开启 Agent 的数据包大小，需 macOS 管理员授权。")}</p>
  {#if status?.supported}
    <div class="block-actions">
      {#if status.installed}
        <button disabled={pending} onclick={()=>confirm('remove')}>{pending?$t("处理中…"):$t("卸载")}</button>
      {:else}
        <button class="primary" disabled={pending} onclick={()=>confirm('install')}>{pending?$t("安装中…"):$t("安装")}</button>
      {/if}
    </div>
  {/if}
  {#if error || status?.phase==='error'}<p class="capture-error" role="alert">{error || status?.message}</p>{/if}
</div>
<dialog bind:this={dialog} aria-labelledby={titleId}>
  <h2 id={titleId}>{mode==='install'?$t("授权安装抓包辅助服务"):$t("卸载抓包辅助服务")}</h2>
  {#if mode==='install'}
    <p>{$t("首次安装需要 macOS 管理员授权。安装完成后，Monitor 再次启动会自动连接服务，无需重新授权或选择进程。")}</p>
    <p>{$t("服务随系统启动，仅在 Monitor 开启采集时抓包，覆盖当前用户所有已开启监测的 Agent，并自动跟随新进程及监测开关变化。")}</p>
    <p>{$t("仅在内存展示发出数据包的 PID、目标地址和 IP 包长度。Monitor 不接收密码，不保存抓包文件，不修改设备权限。可随时停止采集或移除服务；修复、更新服务可能需要再次授权。")}</p>
  {:else}
    <p>{$t("将停止抓包并移除已安装的系统辅助服务。macOS 会要求管理员授权；普通进程和连接监测不受影响。")}</p>
  {/if}
  <div class="actions"><button onclick={()=>dialog.close()}>{$t("取消")}</button><button class="primary" disabled={pending} onclick={submit}>{mode==='install'?$t("授权安装并启用"):$t("确认卸载")}</button></div>
</dialog>
<style>
.card-block{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow);padding:16px;margin-bottom:16px}
.block-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:6px}
h4{margin:0;font-size:13px;font-weight:600;letter-spacing:-.1px}
.block-desc{margin:0;font-size:12px;line-height:1.7;color:var(--text-2)}
.block-actions{display:flex;justify-content:flex-end;gap:8px;margin-top:14px}
.capture-error{margin:12px 0 0;font-size:12px;line-height:1.6;color:var(--red);overflow-wrap:anywhere}
dialog{width:min(480px,calc(100vw - 32px));max-height:calc(100dvh - 48px);overflow:auto;padding:24px;border:1px solid var(--border);border-radius:14px;background:var(--surface);color:var(--text);box-shadow:0 20px 70px #0003}dialog::backdrop{background:#0005;backdrop-filter:blur(4px)}h2{font-size:17px;margin:0 0 16px}dialog p{font-size:12px;line-height:1.8;color:var(--text-2)}.actions{display:flex;justify-content:flex-end;gap:10px;margin-top:20px}
</style>
