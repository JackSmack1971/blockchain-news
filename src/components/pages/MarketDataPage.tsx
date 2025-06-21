import React, { useState } from 'react';
import { TrendingUp, TrendingDown, Search, RefreshCcw, Eye, Star } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { useData } from '@/contexts/DataContext';
import LoadingSpinner from '@/components/ui/LoadingSpinner';

const MarketDataPage: React.FC = () => {
  const { marketData, refreshMarketData, isLoading } = useData();
  const [searchQuery, setSearchQuery] = useState('');
  const [sortBy, setSortBy] = useState('market_cap');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [watchlist, setWatchlist] = useState<string[]>(['bitcoin', 'ethereum']);

  if (isLoading || !marketData) {
    return <LoadingSpinner text="Loading market data..." />;
  }

  // Generate mock chart data
  const generateChartData = () => {
    const data = [];
    const now = new Date();
    for (let i = 23; i >= 0; i--) {
      const time = new Date(now.getTime() - i * 60 * 60 * 1000);
      data.push({
        time: time.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
        bitcoin: 73000 + Math.random() * 1000 - 500,
        ethereum: 4200 + Math.random() * 200 - 100,
        total_market_cap: 2.8 + Math.random() * 0.2 - 0.1,
      });
    }
    return data;
  };

  const chartData = generateChartData();

  const filteredCoins = marketData.coins
    .filter(coin => 
      coin.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      coin.symbol.toLowerCase().includes(searchQuery.toLowerCase())
    )
    .sort((a, b) => {
      const aValue = a[sortBy as keyof typeof a];
      const bValue = b[sortBy as keyof typeof b];
      
      if (typeof aValue === 'number' && typeof bValue === 'number') {
        return sortOrder === 'desc' ? bValue - aValue : aValue - bValue;
      }
      
      return sortOrder === 'desc' 
        ? String(bValue).localeCompare(String(aValue))
        : String(aValue).localeCompare(String(bValue));
    });

  const formatPrice = (price: number) => {
    if (price >= 1000) {
      return `$${price.toLocaleString(undefined, { maximumFractionDigits: 2 })}`;
    }
    return `$${price.toFixed(price < 1 ? 6 : 2)}`;
  };

  const formatMarketCap = (marketCap: number) => {
    if (marketCap >= 1e12) {
      return `$${(marketCap / 1e12).toFixed(2)}T`;
    }
    if (marketCap >= 1e9) {
      return `$${(marketCap / 1e9).toFixed(2)}B`;
    }
    if (marketCap >= 1e6) {
      return `$${(marketCap / 1e6).toFixed(2)}M`;
    }
    return `$${marketCap.toLocaleString()}`;
  };

  const formatVolume = (volume: number) => {
    if (volume >= 1e9) {
      return `$${(volume / 1e9).toFixed(2)}B`;
    }
    if (volume >= 1e6) {
      return `$${(volume / 1e6).toFixed(2)}M`;
    }
    return `$${volume.toLocaleString()}`;
  };

  const formatChange = (change: number) => {
    return `${change >= 0 ? '+' : ''}${change.toFixed(2)}%`;
  };

  const toggleWatchlist = (coinId: string) => {
    setWatchlist(prev => 
      prev.includes(coinId)
        ? prev.filter(id => id !== coinId)
        : [...prev, coinId]
    );
  };

  const handleSort = (field: string) => {
    if (sortBy === field) {
      setSortOrder(sortOrder === 'desc' ? 'asc' : 'desc');
    } else {
      setSortBy(field);
      setSortOrder('desc');
    }
  };

  return (
    <div className="container mx-auto px-4 py-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 mb-8">
        <div>
          <h1 className="text-3xl font-bold mb-2">Cryptocurrency Market Data</h1>
          <p className="text-muted-foreground">
            Real-time prices, market caps, and trading volumes for the top cryptocurrencies
          </p>
        </div>
        <Button onClick={refreshMarketData} className="flex items-center space-x-2">
          <RefreshCcw className="h-4 w-4" />
          <span>Refresh Data</span>
        </Button>
      </div>

      {/* Market Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Total Market Cap
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              ${(marketData.global_stats.total_market_cap / 1e12).toFixed(2)}T
            </div>
            <div className={`flex items-center space-x-1 text-sm ${
              marketData.global_stats.market_cap_change_24h >= 0 
                ? 'text-green-600 dark:text-green-400' 
                : 'text-red-600 dark:text-red-400'
            }`}>
              {marketData.global_stats.market_cap_change_24h >= 0 ? (
                <TrendingUp className="h-4 w-4" />
              ) : (
                <TrendingDown className="h-4 w-4" />
              )}
              <span>{formatChange(marketData.global_stats.market_cap_change_24h)}</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              24h Volume
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              ${(marketData.global_stats.total_volume_24h / 1e9).toFixed(1)}B
            </div>
            <div className="text-sm text-muted-foreground">
              Trading volume in 24h
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Bitcoin Dominance
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {marketData.global_stats.bitcoin_dominance.toFixed(1)}%
            </div>
            <div className="text-sm text-muted-foreground">
              BTC market cap share
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Fear & Greed Index
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {marketData.fear_greed_index.value}
            </div>
            <Badge variant={
              marketData.fear_greed_index.value > 75 ? 'destructive' :
              marketData.fear_greed_index.value > 50 ? 'default' : 'secondary'
            }>
              {marketData.fear_greed_index.classification}
            </Badge>
          </CardContent>
        </Card>
      </div>

      {/* Price Charts */}
      <Card className="mb-8">
        <CardHeader>
          <CardTitle>Market Overview (24h)</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="time" />
                <YAxis />
                <Tooltip />
                <Line 
                  type="monotone" 
                  dataKey="total_market_cap" 
                  stroke="#3B82F6" 
                  strokeWidth={2}
                  name="Market Cap (T)"
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>

      {/* Filters and Search */}
      <div className="flex flex-col md:flex-row gap-4 mb-6">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground h-4 w-4" />
          <Input
            type="search"
            placeholder="Search cryptocurrencies..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-10"
          />
        </div>
        <Select value={sortBy} onValueChange={setSortBy}>
          <SelectTrigger className="w-[180px]">
            <SelectValue placeholder="Sort by" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="market_cap">Market Cap</SelectItem>
            <SelectItem value="price">Price</SelectItem>
            <SelectItem value="change_24h">24h Change</SelectItem>
            <SelectItem value="volume_24h">24h Volume</SelectItem>
            <SelectItem value="name">Name</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Cryptocurrency Table */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <span>Cryptocurrency Prices</span>
            <Badge variant="outline">{filteredCoins.length} coins</Badge>
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-12">#</TableHead>
                  <TableHead 
                    className="cursor-pointer hover:text-primary"
                    onClick={() => handleSort('name')}
                  >
                    Name
                  </TableHead>
                  <TableHead 
                    className="cursor-pointer hover:text-primary text-right"
                    onClick={() => handleSort('price')}
                  >
                    Price
                  </TableHead>
                  <TableHead 
                    className="cursor-pointer hover:text-primary text-right"
                    onClick={() => handleSort('change_24h')}
                  >
                    24h %
                  </TableHead>
                  <TableHead 
                    className="cursor-pointer hover:text-primary text-right"
                    onClick={() => handleSort('market_cap')}
                  >
                    Market Cap
                  </TableHead>
                  <TableHead 
                    className="cursor-pointer hover:text-primary text-right"
                    onClick={() => handleSort('volume_24h')}
                  >
                    Volume (24h)
                  </TableHead>
                  <TableHead className="w-12"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredCoins.map((coin, index) => (
                  <TableRow key={coin.id} className="hover:bg-muted/50">
                    <TableCell className="font-medium text-muted-foreground">
                      {index + 1}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center space-x-3">
                        <img
                          src={coin.logo}
                          alt={coin.name}
                          className="w-8 h-8 rounded-full"
                          onError={(e) => {
                            e.currentTarget.src = '/images/crypto-placeholder.png';
                          }}
                        />
                        <div>
                          <div className="font-medium">{coin.name}</div>
                          <div className="text-sm text-muted-foreground">
                            {coin.symbol.toUpperCase()}
                          </div>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell className="text-right font-medium">
                      {formatPrice(coin.price)}
                    </TableCell>
                    <TableCell className={`text-right font-medium ${
                      coin.change_24h >= 0 
                        ? 'text-green-600 dark:text-green-400' 
                        : 'text-red-600 dark:text-red-400'
                    }`}>
                      <div className="flex items-center justify-end space-x-1">
                        {coin.change_24h >= 0 ? (
                          <TrendingUp className="h-3 w-3" />
                        ) : (
                          <TrendingDown className="h-3 w-3" />
                        )}
                        <span>{formatChange(coin.change_24h)}</span>
                      </div>
                    </TableCell>
                    <TableCell className="text-right">
                      {formatMarketCap(coin.market_cap)}
                    </TableCell>
                    <TableCell className="text-right">
                      {formatVolume(coin.volume_24h)}
                    </TableCell>
                    <TableCell>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => toggleWatchlist(coin.id)}
                        className="h-8 w-8 p-0"
                      >
                        {watchlist.includes(coin.id) ? (
                          <Star className="h-4 w-4 fill-current text-yellow-500" />
                        ) : (
                          <Star className="h-4 w-4" />
                        )}
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default MarketDataPage;
