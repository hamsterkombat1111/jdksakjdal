import React, { useState, useEffect } from 'react';
import './App.css';
import { Tabs, TabsList, TabsTrigger, TabsContent } from './components/ui/tabs';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from './components/ui/dialog';
import { Button } from './components/ui/button';
import { Input } from './components/ui/input';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from './components/ui/card';
import { Badge } from './components/ui/badge';
import { Separator } from './components/ui/separator';
import { Alert, AlertDescription } from './components/ui/alert';
import { Toaster } from './components/ui/sonner';
import { toast } from 'sonner';
import { 
  Info, 
  ExternalLink, 
  Users, 
  AlertTriangle, 
  Shield, 
  LogIn, 
  LogOut, 
  Plus, 
  Trash2, 
  Activity,
  MessageCircle,
  Globe,
  Settings,
  Crown,
  Ban,
  Eye
} from 'lucide-react';
import axios from 'axios';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

function App() {
  const [showDisclaimer, setShowDisclaimer] = useState(true);
  const [showInfoPopup, setShowInfoPopup] = useState(false);
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [user, setUser] = useState(null);
  const [activeTab, setActiveTab] = useState('info');
  
  // Admin states
  const [admins, setAdmins] = useState([]);
  const [blockedIPs, setBlockedIPs] = useState([]);
  const [logs, setLogs] = useState([]);
  const [newAdmin, setNewAdmin] = useState({ name: '', telegram_handle: '' });
  const [blockIP, setBlockIP] = useState({ ip: '', reason: '' });
  const [loginForm, setLoginForm] = useState({ username: '', password: '' });
  
  useEffect(() => {
    // Log visit on app load
    logVisit();
    
    // Check if user is already logged in
    const token = localStorage.getItem('token');
    const userData = localStorage.getItem('user');
    if (token && userData) {
      setUser(JSON.parse(userData));
      setIsLoggedIn(true);
    }
  }, []);

  useEffect(() => {
    if (isLoggedIn && user?.role === 'admin') {
      loadAdminData();
    }
  }, [isLoggedIn, user]);

  const logVisit = async () => {
    try {
      await axios.get(`${BACKEND_URL}/api/visit`);
    } catch (error) {
      console.error('Failed to log visit:', error);
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post(`${BACKEND_URL}/api/login`, loginForm);
      const { token, username, role } = response.data;
      
      localStorage.setItem('token', token);
      localStorage.setItem('user', JSON.stringify({ username, role }));
      setUser({ username, role });
      setIsLoggedIn(true);
      setLoginForm({ username: '', password: '' });
      
      toast.success('Вход выполнен успешно!');
    } catch (error) {
      toast.error('Неверные учетные данные');
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setUser(null);
    setIsLoggedIn(false);
    toast.success('Выход выполнен');
  };

  const loadAdminData = async () => {
    const token = localStorage.getItem('token');
    const config = { headers: { Authorization: `Bearer ${token}` } };
    
    try {
      const [adminsRes, ipsRes, logsRes] = await Promise.all([
        axios.get(`${BACKEND_URL}/api/admins`),
        axios.get(`${BACKEND_URL}/api/blocked-ips`, config),
        axios.get(`${BACKEND_URL}/api/logs`, config)
      ]);
      
      setAdmins(adminsRes.data);
      setBlockedIPs(ipsRes.data);
      setLogs(logsRes.data);
    } catch (error) {
      console.error('Failed to load admin data:', error);
    }
  };

  const addAdmin = async () => {
    if (!newAdmin.name || !newAdmin.telegram_handle) {
      toast.error('Заполните все поля');
      return;
    }
    
    try {
      const token = localStorage.getItem('token');
      const config = { headers: { Authorization: `Bearer ${token}` } };
      
      await axios.post(`${BACKEND_URL}/api/admins`, newAdmin, config);
      setNewAdmin({ name: '', telegram_handle: '' });
      loadAdminData();
      toast.success('Администратор добавлен');
    } catch (error) {
      toast.error('Ошибка при добавлении администратора');
    }
  };

  const deleteAdmin = async (adminId) => {
    try {
      const token = localStorage.getItem('token');
      const config = { headers: { Authorization: `Bearer ${token}` } };
      
      await axios.delete(`${BACKEND_URL}/api/admins/${adminId}`, config);
      loadAdminData();
      toast.success('Администратор удален');
    } catch (error) {
      toast.error('Ошибка при удалении администратора');
    }
  };

  const addBlockedIP = async () => {
    if (!blockIP.ip || !blockIP.reason) {
      toast.error('Заполните все поля');
      return;
    }
    
    try {
      const token = localStorage.getItem('token');
      const config = { headers: { Authorization: `Bearer ${token}` } };
      
      await axios.post(`${BACKEND_URL}/api/block-ip`, blockIP, config);
      setBlockIP({ ip: '', reason: '' });
      loadAdminData();
      toast.success('IP адрес заблокирован');
    } catch (error) {
      toast.error('Ошибка при блокировке IP');
    }
  };

  const unblockIP = async (ipId) => {
    try {
      const token = localStorage.getItem('token');
      const config = { headers: { Authorization: `Bearer ${token}` } };
      
      await axios.delete(`${BACKEND_URL}/api/blocked-ips/${ipId}`, config);
      loadAdminData();
      toast.success('IP адрес разблокирован');
    } catch (error) {
      toast.error('Ошибка при разблокировке IP');
    }
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString('ru-RU');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
      {/* Disclaimer Dialog */}
      <Dialog open={showDisclaimer} onOpenChange={setShowDisclaimer}>
        <DialogContent className="sm:max-w-md bg-slate-800 border-slate-700">
          <DialogHeader>
            <DialogTitle className="text-yellow-400 flex items-center gap-2">
              <AlertTriangle className="h-5 w-5" />
              Внимание!
            </DialogTitle>
            <DialogDescription className="text-slate-300 leading-relaxed">
              Этот сайт создан исключительно в развлекательных целях. 
              Мы не хотим никого оскорбить или унизить.
            </DialogDescription>
          </DialogHeader>
          <div className="flex justify-end">
            <Button 
              onClick={() => setShowDisclaimer(false)}
              className="bg-purple-600 hover:bg-purple-700 text-white"
            >
              Понятно
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      {/* Info Popup Dialog */}
      <Dialog open={showInfoPopup} onOpenChange={setShowInfoPopup}>
        <DialogContent className="sm:max-w-md bg-slate-800 border-slate-700">
          <DialogHeader>
            <DialogTitle className="text-purple-400 flex items-center gap-2">
              <Info className="h-5 w-5" />
              Информация
            </DialogTitle>
            <DialogDescription className="text-slate-300">
              Добро пожаловать на развлекательный сайт! 
              Здесь вы найдете различные интересные материалы и розыгрыши.
              Не забудьте подписаться на наш Telegram канал для получения новых обновлений!
            </DialogDescription>
          </DialogHeader>
          <div className="flex justify-end">
            <Button 
              onClick={() => setShowInfoPopup(false)}
              className="bg-purple-600 hover:bg-purple-700 text-white"
            >
              Закрыть
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      {/* Header */}
      <header className="border-b border-slate-700 bg-slate-800/50 backdrop-blur-lg">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-full bg-gradient-to-r from-purple-500 to-pink-500 flex items-center justify-center">
                <Crown className="h-5 w-5 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-white">PrankVZ</h1>
                <p className="text-sm text-slate-400">Развлекательный портал</p>
              </div>
            </div>
            
            <div className="flex items-center gap-4">
              {isLoggedIn ? (
                <div className="flex items-center gap-3">
                  <div className="flex items-center gap-2">
                    <Badge variant="secondary" className="bg-purple-600 text-white">
                      <Shield className="h-3 w-3 mr-1" />
                      {user?.username}
                    </Badge>
                    {user?.role === 'admin' && (
                      <Badge variant="secondary" className="bg-yellow-600 text-white">
                        <Crown className="h-3 w-3 mr-1" />
                        Админ
                      </Badge>
                    )}
                  </div>
                  <Button 
                    variant="outline" 
                    size="sm" 
                    onClick={handleLogout}
                    className="border-slate-600 text-slate-300 hover:bg-slate-700"
                  >
                    <LogOut className="h-4 w-4 mr-2" />
                    Выйти
                  </Button>
                </div>
              ) : (
                <form onSubmit={handleLogin} className="flex items-center gap-2">
                  <Input
                    type="text"
                    placeholder="Логин"
                    value={loginForm.username}
                    onChange={(e) => setLoginForm({...loginForm, username: e.target.value})}
                    className="w-24 h-8 bg-slate-700 border-slate-600 text-white placeholder:text-slate-400"
                  />
                  <Input
                    type="password"
                    placeholder="Пароль"
                    value={loginForm.password}
                    onChange={(e) => setLoginForm({...loginForm, password: e.target.value})}
                    className="w-24 h-8 bg-slate-700 border-slate-600 text-white placeholder:text-slate-400"
                  />
                  <Button type="submit" size="sm" className="h-8 bg-purple-600 hover:bg-purple-700 text-white">
                    <LogIn className="h-3 w-3 mr-1" />
                    Вход
                  </Button>
                </form>
              )}
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-8">
        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="grid w-full grid-cols-4 bg-slate-800 border-slate-700">
            <TabsTrigger value="info" className="data-[state=active]:bg-purple-600 data-[state=active]:text-white">
              <Info className="h-4 w-4 mr-2" />
              Информация
            </TabsTrigger>
            <TabsTrigger value="buttons" className="data-[state=active]:bg-purple-600 data-[state=active]:text-white">
              <ExternalLink className="h-4 w-4 mr-2" />
              Переходы
            </TabsTrigger>
            <TabsTrigger value="admins" className="data-[state=active]:bg-purple-600 data-[state=active]:text-white">
              <Users className="h-4 w-4 mr-2" />
              Администраторы
            </TabsTrigger>
            <TabsTrigger value="popup" className="data-[state=active]:bg-purple-600 data-[state=active]:text-white">
              <MessageCircle className="h-4 w-4 mr-2" />
              Popup
            </TabsTrigger>
          </TabsList>

          {/* Tab 1: Information */}
          <TabsContent value="info" className="space-y-6">
            <Card className="bg-slate-800 border-slate-700">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Info className="h-5 w-5 text-purple-400" />
                  О проекте PrankVZ
                </CardTitle>
                <CardDescription className="text-slate-400">
                  Развлекательный портал с интересным контентом
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="prose prose-slate prose-invert max-w-none">
                  <p className="text-slate-300 leading-relaxed">
                    Добро пожаловать на PrankVZ - ваш источник развлечений и интересного контента! 
                    Мы создаем уникальные материалы, розыгрыши и забавные истории, которые украсят ваш день.
                  </p>
                  <p className="text-slate-300 leading-relaxed">
                    Наша команда работает над тем, чтобы предоставить вам только качественный и безобидный контент. 
                    Все наши материалы созданы исключительно в развлекательных целях.
                  </p>
                </div>
                
                <Separator className="bg-slate-700" />
                
                <div className="flex flex-col sm:flex-row gap-4">
                  <Button 
                    asChild 
                    className="bg-gradient-to-r from-blue-500 to-cyan-500 hover:from-blue-600 hover:to-cyan-600 text-white shadow-lg"
                  >
                    <a 
                      href="https://t.me/PrankVZ" 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="flex items-center gap-2"
                    >
                      <MessageCircle className="h-4 w-4" />
                      Подписаться на Telegram канал
                      <ExternalLink className="h-3 w-3" />
                    </a>
                  </Button>
                  
                  <Button 
                    variant="outline" 
                    onClick={() => setShowInfoPopup(true)}
                    className="border-slate-600 text-slate-300 hover:bg-slate-700"
                  >
                    <Info className="h-4 w-4 mr-2" />
                    Подробнее
                  </Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Tab 2: 6 Buttons */}
          <TabsContent value="buttons" className="space-y-6">
            <Card className="bg-slate-800 border-slate-700">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <ExternalLink className="h-5 w-5 text-purple-400" />
                  Полезные ссылки
                </CardTitle>
                <CardDescription className="text-slate-400">
                  Коллекция интересных ресурсов
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {[1, 2, 3, 4, 5, 6].map((num) => (
                    <Button
                      key={num}
                      variant="outline"
                      className="h-20 border-slate-600 bg-slate-700/50 hover:bg-slate-600 text-slate-300 hover:text-white transition-all duration-300 group"
                      onClick={() => toast.info(`Кнопка ${num} - настройте ссылку в админ панели`)}
                    >
                      <div className="flex flex-col items-center gap-2">
                        <Globe className="h-6 w-6 group-hover:scale-110 transition-transform" />
                        <span className="font-medium">Кнопка {num}</span>
                      </div>
                    </Button>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Tab 3: Administrators */}
          <TabsContent value="admins" className="space-y-6">
            <Card className="bg-slate-800 border-slate-700">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Users className="h-5 w-5 text-purple-400" />
                  Администраторы канала
                </CardTitle>
                <CardDescription className="text-slate-400">
                  Список администраторов Telegram канала PrankVZ
                </CardDescription>
              </CardHeader>
              <CardContent>
                {admins.length === 0 ? (
                  <div className="text-center py-8">
                    <Users className="h-12 w-12 text-slate-600 mx-auto mb-4" />
                    <p className="text-slate-400">Администраторы не добавлены</p>
                  </div>
                ) : (
                  <div className="grid gap-3">
                    {admins.map((admin) => (
                      <div 
                        key={admin.id} 
                        className="flex items-center justify-between p-4 bg-slate-700/50 rounded-lg border border-slate-600"
                      >
                        <div className="flex items-center gap-3">
                          <div className="w-10 h-10 rounded-full bg-gradient-to-r from-purple-500 to-pink-500 flex items-center justify-center">
                            <Crown className="h-5 w-5 text-white" />
                          </div>
                          <div>
                            <h3 className="font-medium text-white">{admin.name}</h3>
                            <p className="text-sm text-slate-400">@{admin.telegram_handle}</p>
                            <p className="text-xs text-slate-500">Добавлен: {formatDate(admin.created_at)}</p>
                          </div>
                        </div>
                        {isLoggedIn && user?.role === 'admin' && (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => deleteAdmin(admin.id)}
                            className="border-red-600 text-red-400 hover:bg-red-600 hover:text-white"
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        )}
                      </div>
                    ))}
                  </div>
                )}
                
                {isLoggedIn && user?.role === 'admin' && (
                  <>
                    <Separator className="bg-slate-700 my-6" />
                    <div className="space-y-4">
                      <h3 className="text-lg font-medium text-white">Добавить администратора</h3>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <Input
                          placeholder="Имя администратора"
                          value={newAdmin.name}
                          onChange={(e) => setNewAdmin({...newAdmin, name: e.target.value})}
                          className="bg-slate-700 border-slate-600 text-white placeholder:text-slate-400"
                        />
                        <Input
                          placeholder="Telegram handle (без @)"
                          value={newAdmin.telegram_handle}
                          onChange={(e) => setNewAdmin({...newAdmin, telegram_handle: e.target.value})}
                          className="bg-slate-700 border-slate-600 text-white placeholder:text-slate-400"
                        />
                      </div>
                      <Button onClick={addAdmin} className="bg-purple-600 hover:bg-purple-700 text-white">
                        <Plus className="h-4 w-4 mr-2" />
                        Добавить администратора
                      </Button>
                    </div>
                  </>
                )}
              </CardContent>
            </Card>

            {/* Admin Panel */}
            {isLoggedIn && user?.role === 'admin' && (
              <>
                {/* IP Blocking */}
                <Card className="bg-slate-800 border-slate-700">
                  <CardHeader>
                    <CardTitle className="text-white flex items-center gap-2">
                      <Ban className="h-5 w-5 text-red-400" />
                      Блокировка IP адресов
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <Input
                        placeholder="IP адрес"
                        value={blockIP.ip}
                        onChange={(e) => setBlockIP({...blockIP, ip: e.target.value})}
                        className="bg-slate-700 border-slate-600 text-white placeholder:text-slate-400"
                      />
                      <Input
                        placeholder="Причина блокировки"
                        value={blockIP.reason}
                        onChange={(e) => setBlockIP({...blockIP, reason: e.target.value})}
                        className="bg-slate-700 border-slate-600 text-white placeholder:text-slate-400"
                      />
                    </div>
                    <Button onClick={addBlockedIP} className="bg-red-600 hover:bg-red-700 text-white">
                      <Ban className="h-4 w-4 mr-2" />
                      Заблокировать IP
                    </Button>
                    
                    {blockedIPs.length > 0 && (
                      <div className="space-y-2">
                        <h4 className="font-medium text-white">Заблокированные IP:</h4>
                        {blockedIPs.map((ip) => (
                          <div key={ip.id} className="flex items-center justify-between p-3 bg-slate-700/50 rounded border border-slate-600">
                            <div>
                              <span className="text-white font-mono">{ip.ip}</span>
                              <p className="text-sm text-slate-400">{ip.reason}</p>
                              <p className="text-xs text-slate-500">{formatDate(ip.blocked_at)}</p>
                            </div>
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => unblockIP(ip.id)}
                              className="border-green-600 text-green-400 hover:bg-green-600 hover:text-white"
                            >
                              Разблокировать
                            </Button>
                          </div>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>

                {/* Visit Logs */}
                <Card className="bg-slate-800 border-slate-700">
                  <CardHeader>
                    <CardTitle className="text-white flex items-center gap-2">
                      <Activity className="h-5 w-5 text-green-400" />
                      Логи посещений
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    {logs.length === 0 ? (
                      <p className="text-slate-400 text-center py-4">Логи не найдены</p>
                    ) : (
                      <div className="space-y-2 max-h-96 overflow-y-auto">
                        {logs.map((log) => (
                          <div key={log.id} className="p-3 bg-slate-700/50 rounded border border-slate-600">
                            <div className="flex items-center justify-between">
                              <span className="text-white font-mono">{log.ip}</span>
                              <span className="text-xs text-slate-500">{formatDate(log.timestamp)}</span>
                            </div>
                            <p className="text-sm text-slate-400">{log.browser} | {log.os}</p>
                            <p className="text-xs text-slate-500">{log.device} | {log.endpoint}</p>
                          </div>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>
              </>
            )}
          </TabsContent>

          {/* Tab 4: Popup */}
          <TabsContent value="popup" className="space-y-6">
            <Card className="bg-slate-800 border-slate-700">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <MessageCircle className="h-5 w-5 text-purple-400" />
                  Специальное сообщение
                </CardTitle>
                <CardDescription className="text-slate-400">
                  Нажмите кнопку ниже для просмотра сообщения
                </CardDescription>
              </CardHeader>
              <CardContent className="text-center py-8">
                <Button
                  onClick={() => setShowInfoPopup(true)}
                  className="bg-gradient-to-r from-purple-500 to-pink-500 hover:from-purple-600 hover:to-pink-600 text-white text-lg px-8 py-4 shadow-lg"
                >
                  <Eye className="h-5 w-5 mr-2" />
                  Показать сообщение
                </Button>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-700 bg-slate-800/50 backdrop-blur-lg mt-16">
        <div className="container mx-auto px-4 py-6">
          <div className="flex flex-col md:flex-row items-center justify-between">
            <div className="flex items-center gap-2 mb-4 md:mb-0">
              <div className="w-6 h-6 rounded-full bg-gradient-to-r from-purple-500 to-pink-500"></div>
              <span className="text-slate-400">© 2024 PrankVZ. Все права защищены.</span>
            </div>
            <div className="flex items-center gap-4">
              <Button variant="ghost" size="sm" asChild>
                <a href="https://t.me/PrankVZ" target="_blank" rel="noopener noreferrer" className="text-slate-400 hover:text-white">
                  <MessageCircle className="h-4 w-4 mr-2" />
                  Telegram
                </a>
              </Button>
            </div>
          </div>
        </div>
      </footer>

      <Toaster position="bottom-right" />
    </div>
  );
}

export default App;