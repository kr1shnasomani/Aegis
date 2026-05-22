import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Popover, PopoverTrigger, PopoverContent } from "@/components/ui/popover";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useScanQueue } from "@/contexts/ScanQueueContext";
import { useSelectedScan } from "@/contexts/SelectedScanContext";
import {
  Bell,
  CheckCircle2,
  AlertCircle,
  Clock3,
} from "lucide-react";

interface Notification {
  id: string;
  message: string;
  timestamp: Date;
  scanId?: string;
}

function NotificationInboxPopover() {
  const navigate = useNavigate();
  const { notifications: queueNotifications, isRunning, queue } = useScanQueue();
  const { setSelectedScanId } = useSelectedScan();
  const [readIds, setReadIds] = useState<Set<string>>(new Set());
  const [tab, setTab] = useState("all");

  const notifications = useMemo<Notification[]>(() => {
    const dynamicFromQueue = queueNotifications.map((notification) => ({
      id: notification.id,
      message: notification.message,
      timestamp: new Date(notification.timestamp),
      scanId: notification.scanId,
    }));

    const runningItems = queue
      .filter((item) => item.status === "scanning")
      .map((item) => ({
        id: `running-${item.id}`,
        message: `Scan in progress: ${item.target} (${item.currentPhase || "starting"})`,
        timestamp: new Date(),
        scanId: undefined,
      }));

    return [...runningItems, ...dynamicFromQueue];
  }, [queue, queueNotifications]);

  const unreadCount = notifications.filter((n) => !readIds.has(n.id)).length;
  const filtered = tab === "unread" ? notifications.filter((n) => !readIds.has(n.id)) : notifications;

  const formatRelative = (timestamp: Date) => {
    const diffMs = Date.now() - timestamp.getTime();
    const diffMins = Math.max(1, Math.round(diffMs / 60000));
    if (diffMins < 60) return `${diffMins} minute${diffMins === 1 ? "" : "s"} ago`;
    const diffHours = Math.round(diffMins / 60);
    if (diffHours < 24) return `${diffHours} hour${diffHours === 1 ? "" : "s"} ago`;
    const diffDays = Math.round(diffHours / 24);
    return `${diffDays} day${diffDays === 1 ? "" : "s"} ago`;
  };

  const openNotification = (notification: Notification) => {
    setReadIds((prev) => new Set(prev).add(notification.id));
    if (notification.scanId) {
      setSelectedScanId(notification.scanId);
      navigate("/dashboard", { state: { bypassPrompt: true } });
      return;
    }
    navigate("/dashboard/history");
  };

  const markAllAsRead = () => {
    setReadIds(new Set(notifications.map((notification) => notification.id)));
  };

  return (
    <Popover>
      <PopoverTrigger asChild>
        <button className="relative h-8 w-8 rounded-full flex items-center justify-center text-muted-foreground hover:bg-sunken transition-colors">
          <Bell className="w-4 h-4" />
          {unreadCount > 0 && (
            <Badge className="absolute -top-1 -right-1 h-4 min-w-[16px] px-1 flex items-center justify-center text-[10px] leading-none bg-status-critical text-white border-none">
              {unreadCount > 99 ? "99+" : unreadCount}
            </Badge>
          )}
        </button>
      </PopoverTrigger>
      <PopoverContent className="w-[380px] p-0" align="end" sideOffset={8}>
        <div className="flex flex-col">
          <div className="flex items-center justify-between px-4 pt-3 pb-2">
            <Tabs value={tab} onValueChange={setTab}>
              <TabsList className="h-8">
                <TabsTrigger value="all" className="text-xs px-2.5 py-1">All</TabsTrigger>
                <TabsTrigger value="unread" className="text-xs px-2.5 py-1">
                  Unread {unreadCount > 0 && <Badge variant="secondary" className="ml-1 h-4 min-w-4 px-1 text-[10px]">{unreadCount}</Badge>}
                </TabsTrigger>
              </TabsList>
            </Tabs>
            {unreadCount > 0 && (
              <Button variant="ghost" size="sm" className="text-xs text-muted-foreground h-7" onClick={markAllAsRead}>
                Mark all as read
              </Button>
            )}
          </div>

          <div className="max-h-[320px] overflow-y-auto">
            {filtered.length === 0 ? (
              <div className="py-8 text-center text-sm text-muted-foreground">No notifications</div>
            ) : (
              filtered.map((n) => {
                return (
                  <button
                    key={n.id}
                    onClick={() => openNotification(n)}
                    className="flex w-full items-start gap-3 border-b border-border px-4 py-3 text-left hover:bg-sunken transition-colors"
                  >
                    <div className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-sunken">
                      {n.scanId ? (
                        <CheckCircle2 className="h-4 w-4 text-muted-foreground" />
                      ) : isRunning ? (
                        <Clock3 className="h-4 w-4 text-muted-foreground" />
                      ) : (
                        <AlertCircle className="h-4 w-4 text-muted-foreground" />
                      )}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-body text-foreground">{n.message}</p>
                      <p className="text-xs text-muted-foreground mt-0.5">{formatRelative(n.timestamp)}</p>
                    </div>
                    {!readIds.has(n.id) && <div className="mt-2 h-2 w-2 shrink-0 rounded-full bg-brand-accent" />}
                  </button>
                );
              })
            )}
          </div>
        </div>

        <div className="border-t border-border p-2">
          <Button variant="ghost" className="w-full text-xs text-muted-foreground h-8" onClick={() => navigate('/dashboard/history')}>
            View all notifications
          </Button>
        </div>
      </PopoverContent>
    </Popover>
  );
}

export { NotificationInboxPopover };
