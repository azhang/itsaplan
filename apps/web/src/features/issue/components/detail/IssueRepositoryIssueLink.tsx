import { useTranslations } from 'next-intl';
import type { LinkedRepositoryIssue } from '@/lib/api/endpoints/git';
import { GIT_PROVIDER_CONFIG } from '@/utils/gitProviderConfig';
import IssueSourceLink from './IssueSourceLink';

// The repository issue this issue is synced with, under its title, opened on its host. The
// tooltip names the host and the state there.
export default function IssueRepositoryIssueLink({
  issue,
  className,
}: {
  issue: LinkedRepositoryIssue;
  className?: string;
}) {
  const t = useTranslations('issue');
  return (
    <IssueSourceLink
      source={issue.provider}
      href={issue.url}
      external
      tooltip={t(issue.state === 'open' ? 'repositoryIssueOpen' : 'repositoryIssueClosed', {
        provider: GIT_PROVIDER_CONFIG[issue.provider].label,
      })}
      className={className}
    >
      <span dir="ltr">
        {issue.repository}#{issue.number}
      </span>
    </IssueSourceLink>
  );
}
