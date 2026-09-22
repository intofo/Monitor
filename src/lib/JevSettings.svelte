<script lang="ts">
  import Toast from './Toast.svelte';
  import {onMount} from 'svelte';import {invoke} from '@tauri-apps/api/core';import {t} from './preferences';
  let apiUrl=$state('');let model=$state('');let key=$state('');let hasKey=$state(false);let busy=$state(false);let ready=$state(false);let error=$state('');let message=$state('');let changed=$state(false);
  type Status={settings:{api_url:string;model:string};has_key:boolean};
  onMount(()=>{let disposed=false;void invoke<Status>('jev_settings').then(value=>{if(!disposed){apiUrl=value.settings.api_url;model=value.settings.model;hasKey=value.has_key;ready=true;}}).catch(e=>{if(!disposed)error=String(e);});return()=>{disposed=true;};});
  async function save(){busy=true;error='';message='';try{const result=await invoke<Status>('save_jev_settings',{settings:{api_url:apiUrl,model},key:key||null});apiUrl=result.settings.api_url;model=result.settings.model;hasKey=result.has_key;key='';changed=false;message=$t('Jev 配置已保存。');}catch(e){error=String(e);}finally{busy=false;}}
  async function test(){busy=true;error='';message='';try{await invoke('test_jev_connection');message=$t('连接成功，Jev 返回了有效判断。');}catch(e){error=String(e);}finally{busy=false;}}
</script>
<fieldset disabled={busy||!ready}>
  <label>{$t('API 地址')}<input type="url" bind:value={apiUrl} oninput={()=>changed=true} placeholder="https://your-service.example/v1"/></label>
  <label>{$t('模型名称')}<input bind:value={model} oninput={()=>changed=true} placeholder={$t('填写实际模型名称')}/></label>
  <label>API Key<input type="password" autocomplete="new-password" spellcheck="false" bind:value={key} oninput={()=>changed=true} placeholder={hasKey?$t('已保存，留空保持不变'):$t('输入 API Key')}/></label>
  <p>{$t('使用 OpenAI 兼容接口；Key 保存在系统钥匙串。测试连接仅发送模拟事件。')}</p>
  <div class="actions"><button disabled={!hasKey||changed} onclick={test}>{$t('测试连接')}</button><button class="primary" disabled={!apiUrl.trim()||!model.trim()} onclick={save}>{busy?$t('处理中…'):$t('保存')}</button></div>
</fieldset>
{#if message}<Toast message={message}/>{/if}{#if error}<Toast message={error} error/>{/if}
<style>fieldset{border:0;margin:0;padding:0;min-width:0}label{display:flex;flex-direction:column;gap:8px;margin-bottom:18px;font-size:12px}input{width:100%}.actions{display:flex;justify-content:flex-end;gap:8px}p{font-size:12px;line-height:1.7;color:var(--text-2)}</style>
