<script lang="ts">
  import { onMount } from 'svelte';
  import { initializePreferences } from '$lib/preferences';
  onMount(initializePreferences);
  import LiveMonitor from '$lib/LiveMonitor.svelte';
</script>

<svelte:head>
  <title>Monitor</title>
  <meta name="description" content="这台电脑上的 Agent 与监测状态" />
</svelte:head>

<div class="titlebar" data-tauri-drag-region aria-hidden="true"></div>
<main><LiveMonitor /></main>

<style>
  :global(:root){
    --bg:#fafafa;
    --surface:#ffffff;
    --surface-hover:#f5f5f5;
    --border:#ebebeb;
    --border-strong:#dcdcdc;
    --text:#171717;
    --text-2:#6b6b6b;
    --text-3:#a3a3a3;
    --green:#16a34a;
    --red:#dc2626;
    --amber:#b45309;
    --radius:10px;
    --radius-sm:7px;
    --shadow:0 1px 2px rgba(0,0,0,.04);
    --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  }
  :global(:root[data-theme="dark"]){
    --bg:#17181b;--surface:#202226;--surface-hover:#2b2e34;
    --border:#33363d;--border-strong:#474b55;--text:#f0f1f3;
    --text-2:#b0b5bf;--text-3:#858c98;--green:#4ade80;--red:#f87171;--amber:#fbbf24;
  }
  :global(*){box-sizing:border-box}
  :global(html,body){height:100%}
  :global(body){margin:0;background:var(--bg);color:var(--text);font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;font-size:13px;line-height:1.55;-webkit-font-smoothing:antialiased}
  :global(button),:global(input),:global(select){font:inherit;font-size:13px;color:var(--text)}
  :global(input),:global(select){background:var(--surface);border:1px solid var(--border-strong);border-radius:var(--radius-sm);padding:7px 10px;min-width:0}
  :global(select){appearance:none;-webkit-appearance:none;min-height:36px;padding:7px 34px 7px 12px;border-color:var(--border);border-radius:var(--radius);box-shadow:var(--shadow);cursor:pointer;line-height:1.55;background-color:var(--surface);background-image:linear-gradient(45deg,transparent 50%,var(--text-2) 50%),linear-gradient(135deg,var(--text-2) 50%,transparent 50%);background-position:calc(100% - 17px) 50%,calc(100% - 12px) 50%;background-size:5px 5px;background-repeat:no-repeat;transition:background-color .12s,border-color .12s}
  :global(select:hover:not(:disabled)){background-color:var(--surface-hover);border-color:var(--border-strong)}
  :global(select:disabled){opacity:.45;cursor:default}
  :global(select option){background:var(--surface);color:var(--text)}
  :global(input::placeholder){color:var(--text-3)}
  :global(input:focus),:global(select:focus){outline:none;border-color:var(--text);box-shadow:0 0 0 3px color-mix(in srgb,var(--text) 8%,transparent)}
  :global(button){background:var(--surface);border:1px solid var(--border-strong);border-radius:var(--radius-sm);padding:7px 12px;cursor:pointer;white-space:nowrap;transition:background .12s,border-color .12s}
  :global(button:hover:not(:disabled)){background:var(--surface-hover);border-color:#c9c9c9}
  :global(button.primary){background:var(--text);border-color:var(--text);color:var(--surface);font-weight:500}
  :global(button.primary:hover:not(:disabled)){background:var(--text);opacity:.85}
  :global(button:disabled){opacity:.45;cursor:default}
  :global(button:focus-visible),:global(input:focus-visible),:global(select:focus-visible),:global(summary:focus-visible){outline:2px solid var(--text);outline-offset:2px}
  :global(.card){background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow)}
  :global(.muted){color:var(--text-2)}
  :global(code),:global(.mono){font-family:var(--mono);font-size:12px}
  :global(.pill){display:inline-flex;align-items:center;gap:6px;font-size:11px;color:var(--text-2);background:var(--surface-hover);border:1px solid var(--border);border-radius:99px;padding:2px 9px;white-space:nowrap}
  :global(.pill.ok){color:var(--green);background:#f0fdf4;border-color:#bbf7d0}
  :global(.pill.warn){color:var(--amber);background:#fffbeb;border-color:#fde68a}
  :global(.pill.bad){color:var(--red);background:#fef2f2;border-color:#fecaca}
  .titlebar{position:fixed;top:0;left:0;right:0;height:38px;z-index:10;user-select:none;-webkit-user-select:none}
  main{height:100vh;height:100dvh;overflow:hidden}
</style>
