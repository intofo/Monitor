import { derived, writable } from 'svelte/store';
import { english } from './translations';
import { isTauri } from '@tauri-apps/api/core';
import { getCurrentWindow } from '@tauri-apps/api/window';
export type Language = 'zh-CN' | 'en';
export type Theme = 'light' | 'dark' | 'system';
export const language = writable<Language>('zh-CN');
export const theme = writable<Theme>('system');
export const t = derived(language, locale => (text:string, values:Record<string,string|number>={}) => {
  const translated = locale === 'en' ? english[text] ?? text : text;
  return translated.replace(/\{(\w+)\}/g, (match,key) => String(values[key] ?? match));
});
export function initializePreferences() {
  try {
    const stored = JSON.parse(localStorage.getItem('monitor.appearance.v1') ?? '{}');
    if (stored.language === 'zh-CN' || stored.language === 'en') language.set(stored.language);
    if (['light','dark','system'].includes(stored.theme)) theme.set(stored.theme);
  } catch { /* Use defaults when local preferences are unavailable. */ }
  const media = matchMedia('(prefers-color-scheme: dark)');
  let currentLanguage:Language = 'zh-CN';
  let currentTheme:Theme = 'system';
  const save = () => {
    try { localStorage.setItem('monitor.appearance.v1',JSON.stringify({language:currentLanguage,theme:currentTheme})); } catch { /* Keep the current session usable. */ }
  };
  const applyTheme = () => {
    const resolved = currentTheme === 'system' ? (media.matches ? 'dark' : 'light') : currentTheme;
    document.documentElement.dataset.theme = resolved;
    document.documentElement.style.colorScheme = resolved;
    if (isTauri()) void getCurrentWindow().setTheme(currentTheme === 'system' ? null : currentTheme).catch(console.error);
  };
  const stopLanguage = language.subscribe(value => { currentLanguage=value; document.documentElement.lang=value; });
  const stopTheme = theme.subscribe(value => { currentTheme=value; applyTheme(); save(); });
  const stopSaveLanguage = language.subscribe(save);
  media.addEventListener('change',applyTheme);
  return () => { stopLanguage(); stopTheme(); stopSaveLanguage(); media.removeEventListener('change',applyTheme); };
}
