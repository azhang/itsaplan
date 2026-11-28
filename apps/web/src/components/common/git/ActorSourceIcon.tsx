import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { useSourceMark } from '@/hooks/useSourceMark';

// The mark of a source with its name in a tooltip: a repository host, or a source an edition
// adds. It follows the name of someone without an account here, such as the author of a synced
// comment, and precedes the identifier of an issue that came from there. A source with no icon
// shows nothing.
export default function ActorSourceIcon({
  source,
  className,
}: {
  source: string;
  className?: string;
}) {
  const { label, mark } = useSourceMark(source, className);
  if (!mark) return null;
  return (
    <Tooltip>
      <TooltipTrigger asChild>{mark}</TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  );
}
