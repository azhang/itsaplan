import { type ReactNode } from 'react';
import Link from 'next/link';
import { cn } from '@/lib/utils';
import SourceMark from '@/components/common/git/SourceMark';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';

// A small line under an issue's title that names where the issue came from: the source's mark
// and what opens there. The core's line is the repository issue it is synced with; an edition
// draws its own lines with it in IssueTitleExtras.
export default function IssueSourceLink({
  source,
  href,
  external = false,
  tooltip,
  className,
  children,
}: {
  source: string;
  href: string | null;
  external?: boolean;
  tooltip?: string;
  className?: string;
  children: ReactNode;
}) {
  const style = cn(
    'inline-flex max-w-full items-center gap-1.5 text-xs text-muted-foreground',
    href && 'hover:text-foreground',
  );
  const content = (
    <>
      <SourceMark source={source} />
      <span className="truncate">{children}</span>
    </>
  );
  let line = <span className={style}>{content}</span>;
  if (href && external)
    line = (
      <a href={href} target="_blank" rel="noreferrer" className={style}>
        {content}
      </a>
    );
  else if (href)
    line = (
      <Link href={href} className={style}>
        {content}
      </Link>
    );
  return (
    <div className={className}>
      {tooltip ? (
        <Tooltip>
          <TooltipTrigger asChild>{line}</TooltipTrigger>
          <TooltipContent>{tooltip}</TooltipContent>
        </Tooltip>
      ) : (
        line
      )}
    </div>
  );
}
