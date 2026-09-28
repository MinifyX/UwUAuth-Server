import { errorText } from './errors';
import { t } from './i18n';
import { toast } from './toast';

/** Copy `text` and say so. */
export async function copy(text: string) {
  try {
    await navigator.clipboard.writeText(text);
    toast(t('Kopiert ✧'));
  } catch (error) {
    toast(t('Kopieren hat nicht geklappt: {reason}', { reason: errorText(error) }), 'error');
  }
}
