<script lang="ts">
  let {message, error=false}:{message:string;error?:boolean}=$props();
  let element:HTMLDivElement;
  $effect(()=>{
    if(!message||!element)return;
    element.showPopover();
    const timer=setTimeout(()=>element?.hidePopover(),3000);
    return()=>{clearTimeout(timer);element?.hidePopover();};
  });
</script>
<div bind:this={element} popover="manual" class:error role={error?'alert':'status'} aria-live={error?'assertive':'polite'}>
  <span>{message}</span>
</div>
<style>
  div{position:fixed;inset:64px auto auto 50%;transform:translateX(-50%);margin:0;width:max-content;max-width:min(560px,calc(100vw - 40px));box-sizing:border-box;padding:12px 18px;border:1px solid var(--border-strong);border-radius:12px;background:var(--surface);color:var(--text);backdrop-filter:blur(24px);box-shadow:0 8px 32px #0002;font-size:13px;line-height:1.6;overflow-wrap:anywhere}
  div:popover-open{display:flex;align-items:center;gap:16px}
  div.error{color:var(--red)}
</style>
