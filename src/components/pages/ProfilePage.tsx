import React, { useState, useEffect } from 'react';
import { useSearchParams, Navigate } from 'react-router-dom';
import { 
  User, 
  Settings, 
  Bookmark, 
  Bell, 
  Mail, 
  Eye, 
  EyeOff,
  Save,
  Edit3,
  Wallet,
  Shield
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Switch } from '@/components/ui/switch';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Separator } from '@/components/ui/separator';
import { toast } from 'sonner';
import { useAuth } from '@/contexts/AuthContext';
import { useData } from '@/contexts/DataContext';
import ArticleCard from '@/components/ui/ArticleCard';
import { profileUpdateSchema } from '@/lib/validation';

interface SettingsForm {
  notifications: boolean;
  newsletter: boolean;
  categories: string[];
}

const ProfilePage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const { user, isAuthenticated, updateProfile } = useAuth();
  const { articles } = useData();
  
  const [activeTab, setActiveTab] = useState(searchParams.get('tab') || 'profile');
  const [isEditing, setIsEditing] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  
  // Profile form state
  const [profileForm, setProfileForm] = useState({
    username: user?.username || '',
    email: user?.email || '',
    bio: user?.bio || '',
    avatar: user?.avatar || '',
  });

  // Settings form state
  const [settingsForm, setSettingsForm] = useState<SettingsForm>({
    notifications: user?.preferences?.notifications ?? true,
    newsletter: user?.preferences?.newsletter ?? true,
    categories: user?.preferences?.categories || [],
  });

  // Update form when user changes
  useEffect(() => {
    if (user) {
      setProfileForm({
        username: user.username,
        email: user.email || '',
        bio: user.bio || '',
        avatar: user.avatar || '',
      });
      setSettingsForm({
        notifications: user.preferences?.notifications ?? true,
        newsletter: user.preferences?.newsletter ?? true,
        categories: user.preferences?.categories || [],
      });
    }
  }, [user]);

  // Update active tab from URL params
  useEffect(() => {
    const tab = searchParams.get('tab');
    if (tab) {
      setActiveTab(tab);
    }
  }, [searchParams]);

  if (!isAuthenticated) {
    return <Navigate to="/auth" replace />;
  }

  if (!user) {
    return (
      <div className="container mx-auto px-4 py-8">
        <div className="text-center">
          <h2 className="text-2xl font-bold mb-4">Loading Profile...</h2>
        </div>
      </div>
    );
  }

  const bookmarkedArticles = articles.filter(article => 
    user.bookmarks?.includes(article.id)
  );

const handleProfileSave = async () => {
  setIsSaving(true);

  const parsed = profileUpdateSchema.safeParse(profileForm);
  if (!parsed.success) {
    toast.error(parsed.error.errors[0].message);
    setIsSaving(false);
    return;
  }

  const success = await updateProfile(parsed.data);
    
    if (success) {
      toast.success('Profile updated successfully');
      setIsEditing(false);
    } else {
      toast.error('Failed to update profile');
    }
    
    setIsSaving(false);
  };

  const handleSettingsSave = async () => {
    setIsSaving(true);
    
    const success = await updateProfile({
      preferences: {
        notifications: settingsForm.notifications,
        newsletter: settingsForm.newsletter,
        categories: settingsForm.categories,
      },
    });
    
    if (success) {
      toast.success('Settings updated successfully');
    } else {
      toast.error('Failed to update settings');
    }
    
    setIsSaving(false);
  };

  const handleCategoryToggle = (categoryName: string) => {
    setSettingsForm(prev => ({
      ...prev,
      categories: prev.categories.includes(categoryName)
        ? prev.categories.filter(cat => cat !== categoryName)
        : [...prev.categories, categoryName]
    }));
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    });
  };

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="max-w-4xl mx-auto">
        {/* Profile Header */}
        <Card className="mb-8">
          <CardContent className="p-6">
            <div className="flex flex-col md:flex-row items-start md:items-center gap-6">
              <Avatar className="h-24 w-24">
                <AvatarImage src={user.avatar} />
                <AvatarFallback className="text-2xl">
                  {user.username.charAt(0).toUpperCase()}
                </AvatarFallback>
              </Avatar>
              
              <div className="flex-1">
                <div className="flex items-center gap-3 mb-2">
                  <h1 className="text-3xl font-bold">{user.username}</h1>
                  {user.walletAddress && (
                    <Badge variant="outline" className="flex items-center gap-1">
                      <Wallet className="h-3 w-3" />
                      Web3 Connected
                    </Badge>
                  )}
                </div>
                
                {user.email && (
                  <p className="text-muted-foreground mb-2 flex items-center gap-2">
                    <Mail className="h-4 w-4" />
                    {user.email}
                  </p>
                )}
                
                {user.walletAddress && (
                  <p className="text-muted-foreground mb-2 flex items-center gap-2 font-mono text-sm">
                    <Wallet className="h-4 w-4" />
                    {user.walletAddress.slice(0, 6)}...{user.walletAddress.slice(-4)}
                  </p>
                )}
                
                {user.bio && (
                  <p className="text-muted-foreground">{user.bio}</p>
                )}
              </div>

              <div className="flex gap-2">
                <Button
                  variant="outline"
                  onClick={() => setActiveTab('settings')}
                  className="flex items-center gap-2"
                >
                  <Settings className="h-4 w-4" />
                  Settings
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Profile Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="profile" className="flex items-center gap-2">
              <User className="h-4 w-4" />
              Profile
            </TabsTrigger>
            <TabsTrigger value="bookmarks" className="flex items-center gap-2">
              <Bookmark className="h-4 w-4" />
              Bookmarks ({bookmarkedArticles.length})
            </TabsTrigger>
            <TabsTrigger value="settings" className="flex items-center gap-2">
              <Settings className="h-4 w-4" />
              Settings
            </TabsTrigger>
          </TabsList>

          {/* Profile Tab */}
          <TabsContent value="profile" className="space-y-6">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between">
                <CardTitle>Profile Information</CardTitle>
                <Button
                  variant={isEditing ? "outline" : "default"}
                  onClick={() => setIsEditing(!isEditing)}
                  className="flex items-center gap-2"
                >
                  {isEditing ? (
                    <>
                      <Eye className="h-4 w-4" />
                      Cancel
                    </>
                  ) : (
                    <>
                      <Edit3 className="h-4 w-4" />
                      Edit Profile
                    </>
                  )}
                </Button>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="username">Username</Label>
                    <Input
                      id="username"
                      value={profileForm.username}
                      onChange={(e) => setProfileForm(prev => ({ ...prev, username: e.target.value }))}
                      disabled={!isEditing}
                    />
                  </div>
                  
                  <div className="space-y-2">
                    <Label htmlFor="email">Email</Label>
                    <Input
                      id="email"
                      type="email"
                      value={profileForm.email}
                      onChange={(e) => setProfileForm(prev => ({ ...prev, email: e.target.value }))}
                      disabled={!isEditing || !!user.walletAddress}
                    />
                    {user.walletAddress && (
                      <p className="text-xs text-muted-foreground">
                        Email cannot be changed for wallet-connected accounts
                      </p>
                    )}
                  </div>
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="bio">Bio</Label>
                  <Textarea
                    id="bio"
                    value={profileForm.bio}
                    onChange={(e) => setProfileForm(prev => ({ ...prev, bio: e.target.value }))}
                    disabled={!isEditing}
                    placeholder="Tell us about yourself..."
                    rows={3}
                  />
                </div>

                {isEditing && (
                  <div className="flex justify-end gap-2">
                    <Button
                      variant="outline"
                      onClick={() => setIsEditing(false)}
                    >
                      Cancel
                    </Button>
                    <Button
                      onClick={handleProfileSave}
                      disabled={isSaving}
                      className="flex items-center gap-2"
                    >
                      <Save className="h-4 w-4" />
                      {isSaving ? 'Saving...' : 'Save Changes'}
                    </Button>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Account Stats */}
            <Card>
              <CardHeader>
                <CardTitle>Account Statistics</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="text-center p-4 border rounded-lg">
                    <div className="text-2xl font-bold text-blue-600">
                      {bookmarkedArticles.length}
                    </div>
                    <div className="text-sm text-muted-foreground">
                      Bookmarked Articles
                    </div>
                  </div>
                  
                  <div className="text-center p-4 border rounded-lg">
                    <div className="text-2xl font-bold text-green-600">
                      {user.preferences?.categories?.length || 0}
                    </div>
                    <div className="text-sm text-muted-foreground">
                      Followed Categories
                    </div>
                  </div>
                  
                  <div className="text-center p-4 border rounded-lg">
                    <div className="text-2xl font-bold text-purple-600">
                      {user.walletAddress ? 'Web3' : 'Email'}
                    </div>
                    <div className="text-sm text-muted-foreground">
                      Account Type
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Bookmarks Tab */}
          <TabsContent value="bookmarks" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Your Bookmarked Articles</CardTitle>
                <p className="text-muted-foreground">
                  Articles you've saved for later reading
                </p>
              </CardHeader>
              <CardContent>
                {bookmarkedArticles.length > 0 ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    {bookmarkedArticles.map((article) => (
                      <ArticleCard key={article.id} article={article} />
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <Bookmark className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                    <h3 className="text-lg font-semibold mb-2">No bookmarks yet</h3>
                    <p className="text-muted-foreground">
                      Start bookmarking articles you want to read later
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Settings Tab */}
          <TabsContent value="settings" className="space-y-6">
            {/* Notification Settings */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Bell className="h-5 w-5" />
                  Notification Preferences
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <Label htmlFor="notifications">Push Notifications</Label>
                    <p className="text-sm text-muted-foreground">
                      Receive notifications for breaking news and updates
                    </p>
                  </div>
                  <Switch
                    id="notifications"
                    checked={settingsForm.notifications}
                    onCheckedChange={(checked) => 
                      setSettingsForm(prev => ({ ...prev, notifications: checked }))
                    }
                  />
                </div>
                
                <Separator />
                
                <div className="flex items-center justify-between">
                  <div>
                    <Label htmlFor="newsletter">Newsletter Subscription</Label>
                    <p className="text-sm text-muted-foreground">
                      Weekly digest of the most important crypto news
                    </p>
                  </div>
                  <Switch
                    id="newsletter"
                    checked={settingsForm.newsletter}
                    onCheckedChange={(checked) => 
                      setSettingsForm(prev => ({ ...prev, newsletter: checked }))
                    }
                  />
                </div>
              </CardContent>
            </Card>

            {/* Category Preferences */}
            <Card>
              <CardHeader>
                <CardTitle>Content Preferences</CardTitle>
                <p className="text-muted-foreground">
                  Choose which categories to prioritize in your feed
                </p>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {['Market Analysis', 'DeFi', 'NFTs', 'Regulations', 'Technology Updates', 'Institutional'].map((category) => (
                    <div key={category} className="flex items-center space-x-2">
                      <Switch
                        id={category}
                        checked={settingsForm.categories.includes(category)}
                        onCheckedChange={() => handleCategoryToggle(category)}
                      />
                      <Label htmlFor={category}>{category}</Label>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* Account Security */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="h-5 w-5" />
                  Account Security
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {user.walletAddress ? (
                  <div className="p-4 border rounded-lg bg-green-50 dark:bg-green-950/20">
                    <div className="flex items-center gap-2 mb-2">
                      <Wallet className="h-4 w-4 text-green-600" />
                      <span className="font-medium text-green-600">Web3 Wallet Connected</span>
                    </div>
                    <p className="text-sm text-muted-foreground">
                      Your account is secured by your Web3 wallet. No password required.
                    </p>
                    <p className="text-sm font-mono text-muted-foreground mt-2">
                      {user.walletAddress}
                    </p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    <Button variant="outline" className="w-full">
                      Change Password
                    </Button>
                    <Button variant="outline" className="w-full">
                      Enable Two-Factor Authentication
                    </Button>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Save Settings */}
            <div className="flex justify-end">
              <Button
                onClick={handleSettingsSave}
                disabled={isSaving}
                className="flex items-center gap-2"
              >
                <Save className="h-4 w-4" />
                {isSaving ? 'Saving...' : 'Save Settings'}
              </Button>
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

export default ProfilePage;
