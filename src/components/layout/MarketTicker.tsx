import React from 'react';
import { TrendingUp, TrendingDown } from 'lucide-react';
import { useData } from '@/contexts/DataContext';

const MarketTicker: React.FC = () => {
  const { marketData } = useData();

  if (!marketData) return null;

  const topCoins = marketData.coins.slice(0, 8);

  const formatPrice = (price: number) => {
    if (price >= 1000) {
      return `$${price.toLocaleString(undefined, { maximumFractionDigits: 0 })}`;
    }
    return `$${price.toFixed(2)}`;
  };

  const formatChange = (change: number) => {
    return `${change >= 0 ? '+' : ''}${change.toFixed(2)}%`;
  };

  return (
    <div className="bg-muted/30 border-b overflow-hidden">
      <div className="flex animate-scroll whitespace-nowrap py-2">
        {/* Repeat the coins to create seamless scrolling */}
        {[...topCoins, ...topCoins].map((coin, index) => (
          <div key={`${coin.id}-${index}`} className="inline-flex items-center space-x-2 mx-6 text-sm">
            <span className="font-medium text-foreground">
              {coin.symbol}
            </span>
            <span className="text-muted-foreground">
              {formatPrice(coin.price)}
            </span>
            <span className={`flex items-center space-x-1 ${
              coin.change_24h >= 0 ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'
            }`}>
              {coin.change_24h >= 0 ? (
                <TrendingUp className="h-3 w-3" />
              ) : (
                <TrendingDown className="h-3 w-3" />
              )}
              <span>{formatChange(coin.change_24h)}</span>
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};

export default MarketTicker;
