import { useState, useEffect } from 'react';
import { useApi } from '../hooks/useApi';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { 
  Plus, 
  Trash2, 
  Wifi, 
  WifiOff, 
  Copy, 
  Loader2, 
  Monitor,
  Broadcast,
  ExternalLink
} from 'lucide-react';

export default function Devices() {
  const [devices, setDevices] = useState([]);
  const [playlists, setPlaylists] = useState([]);
  const [loading, setLoading] = useState(true);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [assignDialogOpen, setAssignDialogOpen] = useState(false);
  const [broadcastDialogOpen, setBroadcastDialogOpen] = useState(false);
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [deviceName, setDeviceName] = useState('');
  const [selectedPlaylist, setSelectedPlaylist] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const api = useApi();

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const [devicesData, playlistsData] = await Promise.all([
        api.get('/devices'),
        api.get('/playlists')
      ]);
      setDevices(devicesData);
      setPlaylists(playlistsData);
    } catch (error) {
      console.error('Erro ao buscar dados:', error);
      setError('Erro ao carregar dados: ' + error.message);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateDevice = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    try {
      await api.post('/devices', { name: deviceName });
      setCreateDialogOpen(false);
      setDeviceName('');
      setSuccess('Dispositivo criado com sucesso!');
      fetchData();
    } catch (error) {
      setError(error.message);
    }
  };

  const handleDeleteDevice = async (id) => {
    if (!confirm('Tem certeza que deseja excluir este dispositivo?')) return;

    try {
      await api.del(`/devices/${id}`);
      setSuccess('Dispositivo excluído com sucesso!');
      fetchData();
    } catch (error) {
      console.error('Erro ao excluir dispositivo:', error);
      setError('Erro ao excluir dispositivo: ' + error.message);
    }
  };

  const handleAssignPlaylist = async (e) => {
    e.preventDefault();
    if (!selectedDevice || selectedPlaylist === undefined) return;

    try {
      await api.put(`/devices/${selectedDevice._id}`, {
        assignedPlaylistId: selectedPlaylist || null
      });
      setAssignDialogOpen(false);
      setSelectedDevice(null);
      setSelectedPlaylist('');
      setSuccess('Playlist atribuída com sucesso!');
      fetchData();
    } catch (error) {
      console.error('Erro ao atribuir playlist:', error);
      setError('Erro ao atribuir playlist: ' + error.message);
    }
  };

  const handleBroadcastAssign = async (e) => {
    e.preventDefault();
    if (!selectedPlaylist) return;

    try {
      await api.post('/devices/broadcast-assign', {
        playlistId: selectedPlaylist
      });
      setBroadcastDialogOpen(false);
      setSelectedPlaylist('');
      setSuccess('Playlist atribuída a todos os dispositivos!');
      fetchData();
    } catch (error) {
      console.error('Erro ao fazer broadcast:', error);
      setError('Erro ao fazer broadcast: ' + error.message);
    }
  };

  const copyToClipboard = async (text) => {
    try {
      await navigator.clipboard.writeText(text);
      setSuccess('Token copiado para a área de transferência!');
    } catch (error) {
      console.error('Erro ao copiar:', error);
      setError('Erro ao copiar token');
    }
  };

  const openPlayer = (deviceToken) => {
    const playerUrl = api.getPlayerUrl(deviceToken);
    window.open(playerUrl, '_blank');
  };

  const copyPlayerUrl = async (deviceToken) => {
    const playerUrl = api.getPlayerUrl(deviceToken);
    await copyToClipboard(playerUrl);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Dispositivos</h1>
          <p className="text-gray-600">Gerencie os totens digitais do sistema</p>
        </div>
        
        <div className="flex space-x-2">
          <Dialog open={broadcastDialogOpen} onOpenChange={setBroadcastDialogOpen}>
            <DialogTrigger asChild>
              <Button variant="outline">
                <Broadcast className="mr-2 h-4 w-4" />
                Broadcast
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Atribuir Playlist a Todos os Dispositivos</DialogTitle>
              </DialogHeader>
              <form onSubmit={handleBroadcastAssign} className="space-y-4">
                <div className="space-y-2">
                  <Label>Playlist</Label>
                  <Select value={selectedPlaylist} onValueChange={setSelectedPlaylist}>
                    <SelectTrigger>
                      <SelectValue placeholder="Selecione uma playlist" />
                    </SelectTrigger>
                    <SelectContent>
                      {playlists.map((playlist) => (
                        <SelectItem key={playlist._id} value={playlist._id}>
                          {playlist.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                
                <div className="flex justify-end space-x-2">
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => setBroadcastDialogOpen(false)}
                  >
                    Cancelar
                  </Button>
                  <Button type="submit" disabled={!selectedPlaylist}>
                    Atribuir a Todos
                  </Button>
                </div>
              </form>
            </DialogContent>
          </Dialog>

          <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
            <DialogTrigger asChild>
              <Button>
                <Plus className="mr-2 h-4 w-4" />
                Novo Dispositivo
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Criar Novo Dispositivo</DialogTitle>
              </DialogHeader>
              <form onSubmit={handleCreateDevice} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="name">Nome do Dispositivo</Label>
                  <Input
                    id="name"
                    value={deviceName}
                    onChange={(e) => setDeviceName(e.target.value)}
                    required
                    placeholder="Ex: Totem Entrada Principal"
                  />
                </div>
                
                <div className="flex justify-end space-x-2">
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => setCreateDialogOpen(false)}
                  >
                    Cancelar
                  </Button>
                  <Button type="submit" disabled={!deviceName}>
                    Criar
                  </Button>
                </div>
              </form>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {success && (
        <Alert>
          <AlertDescription>{success}</AlertDescription>
        </Alert>
      )}

      {devices.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Monitor className="h-12 w-12 text-gray-400 mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">Nenhum dispositivo encontrado</h3>
            <p className="text-gray-500 text-center mb-4">
              Crie o primeiro dispositivo para começar
            </p>
            <Button onClick={() => setCreateDialogOpen(true)}>
              <Plus className="mr-2 h-4 w-4" />
              Novo Dispositivo
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {devices.map((device) => (
            <Card key={device._id}>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="text-lg">{device.name}</CardTitle>
                  <Badge variant={device.status === 'online' ? 'default' : 'secondary'}>
                    {device.status === 'online' ? (
                      <Wifi className="mr-1 h-3 w-3" />
                    ) : (
                      <WifiOff className="mr-1 h-3 w-3" />
                    )}
                    {device.status === 'online' ? 'Online' : 'Offline'}
                  </Badge>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  <div>
                    <Label className="text-sm text-gray-600">Token</Label>
                    <div className="flex items-center space-x-2 mt-1">
                      <code className="text-xs bg-gray-100 px-2 py-1 rounded flex-1 truncate">
                        {device.deviceToken}
                      </code>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => copyToClipboard(device.deviceToken)}
                      >
                        <Copy className="h-3 w-3" />
                      </Button>
                    </div>
                  </div>
                  
                  <div>
                    <Label className="text-sm text-gray-600">Playlist Atribuída</Label>
                    <div className="mt-1">
                      {device.assignedPlaylistId ? (
                        <span className="text-sm">{device.assignedPlaylistId.name}</span>
                      ) : (
                        <span className="text-sm text-gray-400">Nenhuma playlist atribuída</span>
                      )}
                    </div>
                  </div>
                  
                  <div>
                    <Label className="text-sm text-gray-600">Última Atividade</Label>
                    <div className="text-sm mt-1">
                      {new Date(device.lastSeenAt).toLocaleString('pt-BR')}
                    </div>
                  </div>

                  <div>
                    <Label className="text-sm text-gray-600">URL do Player</Label>
                    <div className="flex items-center space-x-2 mt-1">
                      <code className="text-xs bg-gray-100 px-2 py-1 rounded flex-1 truncate">
                        {api.getPlayerUrl(device.deviceToken)}
                      </code>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => copyPlayerUrl(device.deviceToken)}
                      >
                        <Copy className="h-3 w-3" />
                      </Button>
                    </div>
                  </div>
                </div>
                
                <div className="flex justify-between mt-4 space-x-2">
                  <div className="flex space-x-2">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => openPlayer(device.deviceToken)}
                    >
                      <ExternalLink className="h-4 w-4" />
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => {
                        setSelectedDevice(device);
                        setSelectedPlaylist(device.assignedPlaylistId?._id || '');
                        setAssignDialogOpen(true);
                      }}
                    >
                      Atribuir
                    </Button>
                  </div>
                  <Button
                    size="sm"
                    variant="destructive"
                    onClick={() => handleDeleteDevice(device._id)}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Dialog de Atribuição de Playlist */}
      <Dialog open={assignDialogOpen} onOpenChange={setAssignDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              Atribuir Playlist - {selectedDevice?.name}
            </DialogTitle>
          </DialogHeader>
          <form onSubmit={handleAssignPlaylist} className="space-y-4">
            <div className="space-y-2">
              <Label>Playlist</Label>
              <Select value={selectedPlaylist} onValueChange={setSelectedPlaylist}>
                <SelectTrigger>
                  <SelectValue placeholder="Selecione uma playlist" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="">Nenhuma playlist</SelectItem>
                  {playlists.map((playlist) => (
                    <SelectItem key={playlist._id} value={playlist._id}>
                      {playlist.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            
            <div className="flex justify-end space-x-2">
              <Button
                type="button"
                variant="outline"
                onClick={() => setAssignDialogOpen(false)}
              >
                Cancelar
              </Button>
              <Button type="submit">
                Atribuir
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}