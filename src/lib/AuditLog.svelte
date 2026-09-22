<script lang="ts">
  import { t, language } from './preferences';
  import { invoke,isTauri } from '@tauri-apps/api/core';
  import { save } from '@tauri-apps/plugin-dialog';
  import { onMount } from 'svelte';
  let {agentId, initialBlocked=true, fixedType=false}:{agentId?:string;initialBlocked?:boolean;fixedType?:boolean}=$props();
  let filter=$state<string|null>(null);
  let groups=$state<{agent_id:string;agent_name:string}[]>([]);
  const scope=$derived(agentId??filter);
  const basis:Record<string,string>=$derived({unassigned:$t("未归属 / 历史记录"),process_match:$t("进程名称或路径匹配"),process_ancestry:$t("父子进程关系"),process_observation:$t("进程活动采样"),managed_proxy_session:$t("托管代理会话（非内核身份认证）")});
  type Row={id:number;at_ms:number;category:string;actor:string;target:string;detail:string;enforced:boolean;agent_id:string|null;agent_name:string|null;attribution:string};
  let exporting=$state(false);let exportMessage=$state('');let exportError=$state('');
  let rows=$state<Row[]>([]);let blocked=$state(true);let error=$state('');let generation=0;
  const labels:Record<string,string>=$derived({source_egress_signal:$t("代码外传线索 · 待核查"),process_discovered:$t("发现程序"),policy_changed:$t("规则变更"),launch_requested:$t("代理启动请求"),blocked:$t("已拦截"),agent_started:$t("发现 Agent"),connection:$t("网络连接"),source_open:$t("源码候选文件打开"),connected:$t("代理隧道已连接"),proxy_attempt:$t("代理连接准备"),error:$t("代理异常")});
  async function load(){const current=++generation;try{if(!isTauri())throw new Error($t("请在桌面程序中查看本机持久化日志。"));const [result,allGroups]=await Promise.all([invoke<Row[]>('audit_log',{blockedOnly:blocked,agentId:scope}),invoke<typeof groups>('audit_groups')]);groups=allGroups;if(current===generation){rows=result;error='';}}catch(e){if(current===generation)error=String(e);}}
  async function exportLog(){
    exporting=true;exportError='';exportMessage='';
    const onlyBlocks=blocked;const selectedAgent=scope;
    try{
      if(!isTauri())throw new Error($t("请在桌面程序中导出本机日志。"));
      const stamp=new Date().toISOString().replace(/[:.]/g,'-');
      const path=await save({title:onlyBlocks?$t("导出实际拦截日志"):$t("导出全部保留日志"),defaultPath:`monitor-${onlyBlocks?'blocks':'audit'}-${stamp}.json`,filters:[{name:$t("JSON 日志"),extensions:['json']}]});
      if(!path)return;
      const count=await invoke<number>('export_audit_log',{path,blockedOnly:onlyBlocks,agentId:selectedAgent});
      exportMessage=$t('已导出 {count} 条{kind}记录。',{count,kind:onlyBlocks?$t("实际拦截"):$t("保留")});
    }catch(e){exportError=String(e);}finally{exporting=false;}
  }
  onMount(()=>{blocked=initialBlocked;let stopped=false;let timer:ReturnType<typeof setTimeout>;async function tick(){if(stopped)return;await load();if(!stopped)timer=setTimeout(tick,2500);}void tick();return()=>{stopped=true;++generation;clearTimeout(timer);};});
</script>
<section class="card"><div class="heading"><h2>{blocked?$t("拦截日志"):$t("Agent 活动日志")}</h2><div class="actions"><button disabled={exporting} onclick={exportLog}>{exporting?$t("正在导出…"):$t("导出 JSON")}</button>{#if !fixedType}<select aria-label={$t("日志类型")} bind:value={blocked} onchange={()=>{rows=[];void load();}}><option value={true}>{$t("仅实际拦截")}</option><option value={false}>{$t("全部活动")}</option></select>{/if}</div></div>
{#if agentId===undefined}<select aria-label={$t("按 Agent 筛选日志")} bind:value={filter} onchange={()=>{rows=[];void load();}}><option value={null}>{$t("所有 Agent")}</option><option value="">{$t("未归属 / 历史记录")}</option>{#each groups as group}<option value={group.agent_id}>{group.agent_name}</option>{/each}</select>{/if}

{#if exportMessage}<p role="status">{exportMessage}</p>{/if}
{#if exportError}<p class="error" role="alert">{exportError}</p>{/if}
{#if error}<p class="error" role="alert">{error}</p>{/if}
{#each rows as row}<article><div class="heading"><strong>{labels[row.category] ?? row.category}</strong><small>{new Date(row.at_ms).toLocaleString($language)}</small></div><p><strong>{row.agent_name??$t("未归属")}</strong> · {row.actor}</p><small>{basis[row.attribution]??row.attribution}</small><p class="target">{row.target}</p><p>{row.detail}</p></article>{/each}
{#if !rows.length && !error}<div class="empty">{blocked ? $t("暂未拦截") : $t("尚无活动记录。")}</div>{/if}</section>
<style>
.card{padding:20px;margin:0 0 16px}h2{font-size:13px;font-weight:600;margin:0}.heading{display:flex;justify-content:space-between;align-items:center;gap:12px}p{color:var(--text-2);font-size:12px;line-height:1.7;margin:8px 0}.actions{display:flex;gap:8px;align-items:center}select{margin:10px 0}article{border-top:1px solid var(--border);padding:14px 0}article>div strong{font-size:12px;font-weight:600;color:var(--text)}small{color:var(--text-3);font-size:11px}.target{font-family:var(--mono);overflow-wrap:anywhere}.empty{padding:32px;text-align:center;color:var(--text-3);font-size:12px}.error{color:var(--red)}
</style>
