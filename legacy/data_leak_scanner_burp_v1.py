# -*- coding: utf-8 -*-
import re
from burp import IBurpExtender
from burp import IScannerCheck
from burp import ITab
from java.io import PrintWriter
from javax.swing import JPanel, JLabel, JCheckBox, JTextField, JButton

class BurpExtender(IBurpExtender, IScannerCheck, ITab):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Data Leak Scanner")
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        self._callbacks.registerScannerCheck(self)

        # Создаем GUI
        self.tab = JPanel()

        self.test_mode = JCheckBox("Test Mode", False)
        self.tab.add(self.test_mode)

        self.tab.add(JLabel("Select data types to search:"))
        self.credit_card = JCheckBox("Credit cards", False)
        self.emails = JCheckBox("Email", False)
        self.tab.add(self.credit_card)
        self.tab.add(self.emails)

        self.url_filter = JTextField("", 20) # Поле для фильтрации по URL
        self.method_filter = JTextField("", 10) # Поле для фильтрации по методу запроса
        self.filter_button = JButton("Apply Filter", actionPerformed=self.apply_filter) # Кнопка применения фильтра
    
        filter_panel = JPanel()
        filter_panel.add(JLabel("URL Filter:"))
        filter_panel.add(self.url_filter)
        filter_panel.add(JLabel("Method Filter:"))
        filter_panel.add(self.method_filter)
        filter_panel.add(self.filter_button)
        filter_panel.add(self.test_mode)

        callbacks.customizeUiComponent(filter_panel)
        callbacks.customizeUiComponent(self.tab)
        callbacks.addSuiteTab(self)

    # Методы ITab
    def getTabCaption(self):
        return "Data Leak Scanner"

    def getUiComponent(self):
        return self.tab

    def doPassiveScan(self, baseRequestResponse):
        self.stdout.println("doPassiveScan called")
        # Получаем ответ
        response = baseRequestResponse.getResponse()
        analyzedResponse = self._helpers.bytesToString(response)

        # Получаем состояние чекбоксов
        search_credit_cards = self.credit_card.isSelected()
        search_emails = self.emails.isSelected()

        # Получаем состояние чекбокса тестового режима
        test_mode = self.test_mode.isSelected()

        # Задаем шаблон для поиска утечек
        leak_pattern = ''
        if search_credit_cards:
            leak_pattern += r'\b(?:\d[ -]*?){13,16}\b'
        if search_emails:
            leak_pattern += r'|(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b)'

        # Ищем совпадения
        leaks = re.findall(leak_pattern, analyzedResponse)

        if leaks:
            if test_mode:
                with open("leaks_test.txt", "a") as file:
                  for leak in leaks:
                    file.write("Potential data leak found: %s\n" % leak)
            else:
               with open("leaks.txt", "a") as file:
                 for leak in leaks:
                    file.write("Potential data leak found: %s\n" % leak)

            return [self._callbacks.applyMarkers(baseRequestResponse, None, None)]

        return None

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueDetail() == newIssue.getIssueDetail():
            return -1 
        else:
            return 0

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        self.stdout.println("doActiveScan called")
        return None
    
    def apply_filter(self, e):
        self.stdout.println("Applying Filter...")

        url_filter = self.url_filter.getText()
        method_filter = self.method_filter.getText()

        self.stdout.println("URL Filter: " + url_filter)
        self.stdout.println("Method Filter: " + method_filter)

            # Здесь вы можете применить фильтры к результатам сканирования
            # И вывести только те, которые соответствуют фильтрам
            # Например, можно использовать self._callbacks.applyMarkers(baseRequestResponse, None, None) для подсветки результатов

        self.stdout.println("Filter Applied.")

