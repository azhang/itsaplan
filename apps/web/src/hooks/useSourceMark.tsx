import { useTranslations } from 'next-intl';
import { cn } from '@/lib/utils';
import { GIT_CONNECTION_PROVIDERS, GIT_PROVIDER_CONFIG } from '@/utils/gitProviderConfig';
import { actorSourceIcons } from '@/cloud';
import GitHostMark from '@/components/common/git/GitHostMark';

// A source's name and mark: a repository host, or a source an edition adds, whose icon is in
// `actorSourceIcons` and whose name is in `common.actorSource.<key>`. A source with no icon
// has no mark.
export function useSourceMark(source: string, className?: string) {
  const t = useTranslations('common');
  const host = GIT_CONNECTION_PROVIDERS.find((one) => one === source);
  const Icon = actorSourceIcons[source];
  const key = `actorSource.${source}` as Parameters<typeof t.has>[0];
  let label = source;
  if (host) label = t('fromHost', { host: GIT_PROVIDER_CONFIG[host].label });
  else if (t.has(key)) label = t(key);
  const props = {
    role: 'img',
    'aria-label': label,
    className: cn('size-3 shrink-0 text-muted-foreground', className),
  };
  let mark = null;
  if (host) mark = <GitHostMark host={host} {...props} />;
  else if (Icon) mark = <Icon {...props} />;
  return { label, mark };
}
