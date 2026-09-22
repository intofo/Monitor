<script lang="ts">
  import { t, language } from './preferences';
  import { invoke, isTauri } from '@tauri-apps/api/core';
  import { agentIcons } from './agent-icons';
  let { id, name }: { id:string; name:string } = $props();
  let icon = $state<string|null>(null);
  $effect(() => {
    const agentId = id;
    let active = true;
    const bundled = agentIcons[agentId] ?? null;
    icon = bundled;
    if (!bundled && isTauri()) {
      void invoke<string|null>('agent_icon', { id: agentId })
        .then(value => { if (active) icon = value; })
        .catch(() => {});
    }
    return () => { active = false; };
  });
</script>
{#if icon}<img src={icon} alt={$t('{name} 图标',{name})} width="32" height="32" onerror={()=>icon=null} />{:else}<span class="fallback" title={$t("未获取到应用图标，使用名称标识")} aria-label={$t('{name} 名称标识',{name})}>{name.slice(0,2).toUpperCase()}</span>{/if}
<style>img{object-fit:contain;flex-shrink:0;width:32px;height:32px}.fallback{display:grid;place-items:center;width:32px;height:32px;border-radius:8px;background:var(--surface-hover);border:1px solid var(--border);color:var(--text-2);font-size:11px;font-weight:600;letter-spacing:.3px;flex-shrink:0}</style>
