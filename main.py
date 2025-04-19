import sys
import ccxt
import time
from concurrent.futures import ThreadPoolExecutor
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QLabel, QComboBox, QPushButton, QTableWidget, QTableWidgetItem,
                             QDoubleSpinBox, QCheckBox, QProgressBar, QMessageBox, QTabWidget,
                             QGroupBox, QLineEdit, QFileDialog, QProgressDialog)
from PyQt5.QtCore import Qt, QTimer, QCoreApplication
from PyQt5.QtGui import QColor
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas

# List of CCXT exchanges
POTENTIAL_EXCHANGES = [
    'binance', 'kucoin', 'huobi', 'okx', 'bybit', 'gateio', 
    'bitget', 'mexc', 'bitmart', 'whitebit', 'hitbtc', 'bitfinex',
    'bittrex', 'poloniex', 'gemini', 'kraken', 'coinbase', 'bitstamp',
    'lbank', 'digifinex', 'zb', 'bitrue', 'exmo', 'bitforex'
]

class CryptoArbitrageApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cryptocurrency Arbitrage Scanner - R.N")
        self.setGeometry(100, 100, 1200, 800)
        
        # Program variables
        self.active_exchanges = []
        self.arbitrage_opportunities = []
        self.current_results = []
        self.is_scanning = False
        self.MAX_PROFIT_PERCENT = 200  # Maximum allowed profit percentage
        
        # Initialize UI
        self.init_ui()
        
        # Initial check for active exchanges
        self.check_active_exchanges()
        
    def init_ui(self):
        """Initialize the user interface"""
        main_widget = QWidget()
        main_layout = QHBoxLayout()
        
        # Main tabs
        self.tabs = QTabWidget()
        
        # Scan tab
        self.create_scan_tab()
        
        # Results tab
        self.create_results_tab()
        
        # Settings tab
        self.create_settings_tab()
        
        main_layout.addWidget(self.tabs)
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)
        
        # Status bar
        self.status_label = QLabel("Ready")
        self.statusBar().addPermanentWidget(self.status_label)
        
    def create_scan_tab(self):
        """Create the scan tab"""
        scan_tab = QWidget()
        layout = QVBoxLayout()
        
        # Exchange selection group
        exchange_group = QGroupBox("Exchange Settings")
        exchange_layout = QVBoxLayout()
        
        # Base exchange selection
        self.base_exchange_combo = QComboBox()
        self.refresh_exchanges_btn = QPushButton("Refresh Active Exchanges")
        self.refresh_exchanges_btn.clicked.connect(self.check_active_exchanges)
        
        # Comparison exchanges list
        self.compare_exchanges_list = QWidget()
        self.compare_exchanges_list.setFixedHeight(150)
        self.compare_exchanges_layout = QVBoxLayout()
        self.compare_exchanges_list.setLayout(self.compare_exchanges_layout)
        
        exchange_layout.addWidget(QLabel("Base Exchange:"))
        exchange_layout.addWidget(self.base_exchange_combo)
        exchange_layout.addWidget(QLabel("Compare with:"))
        exchange_layout.addWidget(self.compare_exchanges_list)
        exchange_layout.addWidget(self.refresh_exchanges_btn)
        exchange_group.setLayout(exchange_layout)
        
        # Scan settings group
        settings_group = QGroupBox("Scan Settings")
        settings_layout = QVBoxLayout()
        
        self.threshold_spin = QDoubleSpinBox()
        self.threshold_spin.setRange(0.1, 100)
        self.threshold_spin.setValue(3.0)
        self.threshold_spin.setSuffix("%")
        
        self.auto_scan_check = QCheckBox("Auto scan every")
        self.auto_scan_interval = QDoubleSpinBox()
        self.auto_scan_interval.setRange(1, 60)
        self.auto_scan_interval.setValue(1)
        self.auto_scan_interval.setSuffix(" minutes")
        
        self.start_btn = QPushButton("Start Scan")
        self.start_btn.clicked.connect(self.start_scan)
        
        settings_layout.addWidget(QLabel("Minimum price difference:"))
        settings_layout.addWidget(self.threshold_spin)
        settings_layout.addWidget(self.auto_scan_check)
        settings_layout.addWidget(self.auto_scan_interval)
        settings_layout.addWidget(self.start_btn)
        settings_group.setLayout(settings_layout)
        
        # Scan progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        layout.addWidget(exchange_group)
        layout.addWidget(settings_group)
        layout.addStretch(1)
        layout.addWidget(self.progress_bar)
        scan_tab.setLayout(layout)
        
        self.tabs.addTab(scan_tab, "Arbitrage Scan")
    
    def create_results_tab(self):
        """Create the results tab"""
        results_tab = QWidget()
        layout = QVBoxLayout()
        
        # Results filters
        filter_group = QGroupBox("Filters")
        filter_layout = QHBoxLayout()
        
        self.min_profit_filter = QDoubleSpinBox()
        self.min_profit_filter.setRange(0, 100)
        self.min_profit_filter.setValue(5.0)
        self.min_profit_filter.setSuffix("%")
        
        self.exchange_filter = QComboBox()
        self.exchange_filter.addItem("All Exchanges")
        
        self.symbol_filter = QLineEdit()
        self.symbol_filter.setPlaceholderText("Symbol filter...")
        
        self.apply_filter_btn = QPushButton("Apply Filters")
        self.apply_filter_btn.clicked.connect(self.apply_filters)
        
        self.export_btn = QPushButton("Save Results")
        self.export_btn.clicked.connect(self.export_results)
        
        filter_layout.addWidget(QLabel("Min. difference:"))
        filter_layout.addWidget(self.min_profit_filter)
        filter_layout.addWidget(QLabel("Exchange:"))
        filter_layout.addWidget(self.exchange_filter)
        filter_layout.addWidget(QLabel("Symbol:"))
        filter_layout.addWidget(self.symbol_filter)
        filter_layout.addWidget(self.apply_filter_btn)
        filter_layout.addWidget(self.export_btn)
        filter_group.setLayout(filter_layout)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setMinimumHeight(400)
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels([
            "Symbol", "Exchange", "Base Price", "Compare Price", "Profit %", "Trade Direction"
        ])
        self.results_table.setSortingEnabled(True)
        self.results_table.doubleClicked.connect(self.show_chart)
        
        # Chart
        self.figure = plt.figure()
        self.canvas = FigureCanvas(self.figure)
        
        layout.addWidget(filter_group)
        layout.addWidget(self.results_table)
        layout.addWidget(self.canvas)
        results_tab.setLayout(layout)
        
        self.tabs.addTab(results_tab, "Results")
    
    def create_settings_tab(self):
        """Create the settings tab"""
        settings_tab = QWidget()
        layout = QVBoxLayout()
        
        # General settings
        general_group = QGroupBox("General Settings")
        general_layout = QVBoxLayout()
        
        general_layout.addWidget(QLabel("Additional settings will be added in future updates"))
        
        general_group.setLayout(general_layout)
        layout.addWidget(general_group)
        settings_tab.setLayout(layout)
        
        self.tabs.addTab(settings_tab, "Settings")
    
    def check_active_exchanges(self):
        """Check which exchanges are active"""
        self.status_label.setText("Checking active exchanges...")
        self.refresh_exchanges_btn.setEnabled(False)
        
        # Create progress dialog
        progress = QProgressDialog("Checking active exchanges...", "Cancel", 0, len(POTENTIAL_EXCHANGES), self)
        progress.setWindowModality(Qt.WindowModal)
        progress.setWindowTitle("Checking Exchanges")
        progress.show()
        
        try:
            with ThreadPoolExecutor() as executor:
                futures = []
                for exchange_id in POTENTIAL_EXCHANGES:
                    futures.append(executor.submit(self.check_exchange_active, exchange_id))
                
                self.active_exchanges = []
                for i, future in enumerate(futures, start=1):
                    if progress.wasCanceled():
                        break
                    
                    exchange_id, is_active = future.result()
                    if is_active:
                        self.active_exchanges.append(exchange_id)
                    
                    progress.setValue(i)
                    progress.setLabelText(f"Checking {exchange_id}...")
                    QCoreApplication.processEvents()
        
        finally:
            progress.close()
            self.update_exchange_ui()
            self.status_label.setText(f"Found {len(self.active_exchanges)} active exchanges")
            self.refresh_exchanges_btn.setEnabled(True)
    
    def check_exchange_active(self, exchange_id):
        """Check if an exchange is active"""
        try:
            exchange = getattr(ccxt, exchange_id)()
            markets = exchange.load_markets()
            return exchange_id, len(markets) > 0
        except Exception as e:
            print(f"Error checking {exchange_id}: {str(e)}")
            return exchange_id, False
    
    def update_exchange_ui(self):
        """Update UI based on active exchanges"""
        self.base_exchange_combo.clear()
        self.base_exchange_combo.addItems(self.active_exchanges)
        
        # Clear previous checkboxes
        for i in reversed(range(self.compare_exchanges_layout.count())): 
            self.compare_exchanges_layout.itemAt(i).widget().setParent(None)
        
        # Create checkboxes for each active exchange (except base)
        for exchange in self.active_exchanges:
            if exchange != self.base_exchange_combo.currentText():
                cb = QCheckBox(exchange)
                cb.setChecked(True)
                self.compare_exchanges_layout.addWidget(cb)
        
        # Update exchange filter in results tab
        self.exchange_filter.clear()
        self.exchange_filter.addItem("All Exchanges")
        self.exchange_filter.addItems(self.active_exchanges)
    
    def start_scan(self):
        """Start arbitrage scanning"""
        if self.is_scanning:
            return
            
        self.is_scanning = True
        self.start_btn.setEnabled(False)
        self.status_label.setText("Scanning started...")
        QApplication.processEvents()
        
        base_exchange = self.base_exchange_combo.currentText()
        
        # Get selected comparison exchanges
        compare_exchanges = []
        for i in range(self.compare_exchanges_layout.count()):
            cb = self.compare_exchanges_layout.itemAt(i).widget()
            if cb.isChecked():
                compare_exchanges.append(cb.text())
        
        if not compare_exchanges:
            QMessageBox.warning(self, "Error", "Please select at least one exchange to compare with")
            self.is_scanning = False
            self.start_btn.setEnabled(True)
            self.status_label.setText("Ready")
            return
        
        threshold = self.threshold_spin.value()
        
        # Create progress dialog
        progress = QProgressDialog("Scanning for arbitrage opportunities...", "Cancel", 0, len(compare_exchanges)+1, self)
        progress.setWindowModality(Qt.WindowModal)
        progress.setWindowTitle("Arbitrage Scan")
        progress.show()
        
        try:
            with ThreadPoolExecutor() as executor:
                # Get data from base exchange with bid/ask prices
                progress.setLabelText(f"Fetching data from {base_exchange}...")
                progress.setValue(1)
                QCoreApplication.processEvents()
                
                base_tickers = executor.submit(get_exchange_tickers_with_bid_ask, base_exchange).result()
                
                if progress.wasCanceled():
                    return
                
                # Get data from comparison exchanges
                compare_results = []
                futures = []
                for exchange in compare_exchanges:
                    futures.append(executor.submit(get_exchange_tickers, exchange))
                
                for i, future in enumerate(futures, start=2):
                    if progress.wasCanceled():
                        break
                    
                    progress.setLabelText(f"Fetching data from {compare_exchanges[i-2]}...")
                    progress.setValue(i)
                    QCoreApplication.processEvents()
                    
                    compare_results.append(future.result())
                
                if progress.wasCanceled():
                    return
                
                # Process results
                progress.setLabelText("Processing results...")
                progress.setValue(len(compare_exchanges)+1)
                QCoreApplication.processEvents()
                
                self.process_results(base_exchange, base_tickers, compare_exchanges, compare_results, threshold)
                
                self.status_label.setText(f"Scan complete. Found {len(self.current_results)} opportunities")
                
                # Show results in results tab
                self.tabs.setCurrentIndex(1)
                self.display_results()
                
        except Exception as e:
            self.status_label.setText(f"Error during scan: {str(e)}")
            QMessageBox.critical(self, "Error", f"An error occurred during scanning: {str(e)}")
        finally:
            progress.close()
            self.is_scanning = False
            self.start_btn.setEnabled(True)
            
            # If auto scan is enabled, set timer
            if self.auto_scan_check.isChecked() and not progress.wasCanceled():
                interval = self.auto_scan_interval.value() * 60 * 1000  # convert to milliseconds
                QTimer.singleShot(int(interval), self.start_scan)
    
    def process_results(self, base_exchange, base_tickers, compare_exchanges, compare_results, threshold):
        """Process scan results"""
        normalized_base = {normalize_symbol(k): v for k, v in base_tickers.items()}
        
        opportunities = []
        for exchange, tickers in zip(compare_exchanges, compare_results):
            normalized_compare = {normalize_symbol(k): v for k, v in tickers.items()}
            
            common_symbols = set(normalized_base.keys()) & set(normalized_compare.keys())
            for symbol in common_symbols:
                base_data = normalized_base[symbol]
                compare_price = normalized_compare[symbol]
                
                # Skip if bid or ask is not available
                if not hasattr(base_data, 'bid') or not hasattr(base_data, 'ask'):
                    continue
                
                # Calculate bid-ask spread percentage in base exchange
                bid = base_data.bid
                ask = base_data.ask
                if bid and ask and bid > 0:
                    spread_percent = ((ask - bid) / bid) * 100
                    
                    # Skip if bid-ask spread is more than 5%
                    if spread_percent > 5:
                        continue
                
                base_price = base_data.last if hasattr(base_data, 'last') else None
                
                if base_price and compare_price and base_price > 0 and compare_price > 0:
                    profit_percent = ((compare_price - base_price) / base_price) * 100
                    
                    # Skip if profit is too high (likely data error)
                    if abs(profit_percent) > self.MAX_PROFIT_PERCENT:
                        continue
                    
                    if abs(profit_percent) >= threshold:
                        direction = f"Buy from {base_exchange} → Sell on {exchange}" if profit_percent > 0 else f"Buy from {exchange} → Sell on {base_exchange}"
                        opportunities.append({
                            'symbol': symbol,
                            'exchange': exchange,
                            'base_price': base_price,
                            'compare_price': compare_price,
                            'profit_percent': abs(profit_percent),
                            'direction': direction
                        })
        
        # Sort by profit percentage (ascending)
        opportunities.sort(key=lambda x: x['profit_percent'])
        
        self.arbitrage_opportunities = opportunities
        self.current_results = opportunities.copy()
    
    def display_results(self):
        """Display results in table"""
        self.results_table.setRowCount(len(self.current_results))
        
        for row, opp in enumerate(self.current_results):
            self.results_table.setItem(row, 0, QTableWidgetItem(opp['symbol']))
            self.results_table.setItem(row, 1, QTableWidgetItem(opp['exchange']))
            self.results_table.setItem(row, 2, QTableWidgetItem(f"{opp['base_price']:.8f}"))
            self.results_table.setItem(row, 3, QTableWidgetItem(f"{opp['compare_price']:.8f}"))
            
            # Color coding profit based on value
            profit_item = QTableWidgetItem(f"{opp['profit_percent']:.2f}%")
            if opp['profit_percent'] > 20:
                profit_item.setBackground(QColor(0, 255, 0, 100))  # Green for high profit
            elif opp['profit_percent'] > 10:
                profit_item.setBackground(QColor(144, 238, 144, 100))  # Light green
            else:
                profit_item.setBackground(QColor(173, 216, 230, 100))  # Light blue
            self.results_table.setItem(row, 4, profit_item)
            
            self.results_table.setItem(row, 5, QTableWidgetItem(opp['direction']))
        
        # Sort by profit percentage (ascending) by default
        self.results_table.sortItems(4, Qt.AscendingOrder)
        self.results_table.resizeColumnsToContents()
    
    def apply_filters(self):
        """Apply filters to results"""
        min_profit = self.min_profit_filter.value()
        exchange_filter = self.exchange_filter.currentText()
        symbol_filter = self.symbol_filter.text().upper()
        
        filtered_results = []
        for opp in self.arbitrage_opportunities:
            if (opp['profit_percent'] >= min_profit and
                (exchange_filter == "All Exchanges" or opp['exchange'] == exchange_filter) and
                (symbol_filter == "" or symbol_filter in opp['symbol'])):
                filtered_results.append(opp)
        
        self.current_results = filtered_results
        self.display_results()
        self.status_label.setText(f"{len(filtered_results)} results after filtering")
    
    def export_results(self):
        """Save results to file"""
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getSaveFileName(
            self, "Save Results", "", "CSV Files (*.csv);;All Files (*)", options=options)
        
        if file_name:
            try:
                with open(file_name, 'w', encoding='utf-8') as f:
                    f.write("Symbol,Exchange,Base Price,Compare Price,Profit %,Trade Direction\n")
                    for opp in self.current_results:
                        f.write(f"{opp['symbol']},{opp['exchange']},{opp['base_price']:.8f},")
                        f.write(f"{opp['compare_price']:.8f},{opp['profit_percent']:.2f}%,")
                        f.write(f"{opp['direction']}\n")
                
                self.status_label.setText(f"Results saved to {file_name}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Error saving file: {str(e)}")
    
    def show_chart(self, item):
        """Show chart for selected symbol"""
        row = item.row()
        symbol = self.results_table.item(row, 0).text()
        exchange = self.results_table.item(row, 1).text()
        base_price = float(self.results_table.item(row, 2).text())
        compare_price = float(self.results_table.item(row, 3).text())
        
        self.figure.clear()
        ax = self.figure.add_subplot(111)
        
        prices = [base_price, compare_price]
        labels = [self.base_exchange_combo.currentText(), exchange]
        
        ax.bar(labels, prices, color=['blue', 'green'])
        ax.set_title(f"Price Comparison for {symbol}")
        ax.set_ylabel("Price")
        
        # Add numeric values on the chart
        for i, v in enumerate(prices):
            ax.text(i, v, f"{v:.8f}", ha='center', va='bottom')
        
        self.canvas.draw()

def get_exchange_tickers(exchange_name):
    """Get tickers from an exchange (last price only)"""
    try:
        exchange = getattr(ccxt, exchange_name)()
        tickers = exchange.fetch_tickers()
        return {symbol: ticker['last'] for symbol, ticker in tickers.items() if ticker.get('last')}
    except Exception as e:
        print(f"Error getting data from {exchange_name}: {str(e)}")
        return {}

def get_exchange_tickers_with_bid_ask(exchange_name):
    """Get tickers from an exchange including bid and ask prices"""
    try:
        exchange = getattr(ccxt, exchange_name)()
        tickers = exchange.fetch_tickers()
        
        # Create a simple class to hold the ticker data
        class TickerData:
            def __init__(self, last, bid, ask):
                self.last = last
                self.bid = bid
                self.ask = ask
        
        return {
            symbol: TickerData(
                ticker.get('last'),
                ticker.get('bid'),
                ticker.get('ask')
            )
            for symbol, ticker in tickers.items()
            if ticker.get('last') is not None
        }
    except Exception as e:
        print(f"Error getting data from {exchange_name}: {str(e)}")
        return {}

def normalize_symbol(symbol):
    """Normalize symbols"""
    return symbol.replace('/', '').replace('-', '').upper()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CryptoArbitrageApp()
    window.show()
    sys.exit(app.exec_())
