using System.Windows;
using System.Windows.Controls;
using JustCryptDns.App.ViewModels;

namespace JustCryptDns.App.Views;

public partial class ConnectionMonitorView : UserControl
{
    private Window? _hostWindow;
    private ConnectionMonitorViewModel? _boundVm;

    public ConnectionMonitorView()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
        IsVisibleChanged += OnIsVisibleChanged;
        DataContextChanged += OnDataContextChanged;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (_hostWindow is not null)
        {
            _hostWindow.StateChanged -= OnVisibilityOrStateChanged;
        }

        _hostWindow = Window.GetWindow(this);
        if (_hostWindow is not null)
        {
            _hostWindow.StateChanged += OnVisibilityOrStateChanged;
        }

        if (_boundVm is null && DataContext is ConnectionMonitorViewModel vm)
        {
            _boundVm = vm;
            _boundVm.AutoScrollRequested += OnAutoScrollRequested;
            _boundVm.EditNoteRequested += OnEditNoteRequested;
        }

        UpdateWindowActiveState();
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        if (_hostWindow is not null)
        {
            _hostWindow.StateChanged -= OnVisibilityOrStateChanged;
            _hostWindow = null;
        }

        DetachViewModelEvents();
    }

    private void OnDataContextChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        DetachViewModelEvents();
        if (e.NewValue is ConnectionMonitorViewModel vm)
        {
            _boundVm = vm;
            _boundVm.AutoScrollRequested += OnAutoScrollRequested;
            _boundVm.EditNoteRequested += OnEditNoteRequested;
            UpdateWindowActiveState();
        }
    }

    private void DetachViewModelEvents()
    {
        if (_boundVm is not null)
        {
            _boundVm.AutoScrollRequested -= OnAutoScrollRequested;
            _boundVm.EditNoteRequested -= OnEditNoteRequested;
            _boundVm = null;
        }
    }

    private void OnIsVisibleChanged(object sender, DependencyPropertyChangedEventArgs e) => UpdateWindowActiveState();

    private void OnVisibilityOrStateChanged(object? sender, EventArgs e) => UpdateWindowActiveState();

    private void UpdateWindowActiveState()
    {
        if (DataContext is not ConnectionMonitorViewModel vm)
        {
            return;
        }

        var isWindowMinimized = _hostWindow?.WindowState == WindowState.Minimized;
        vm.SetWindowActive(IsVisible && !isWindowMinimized);
    }

    private void OnGridBeginningEdit(object? sender, DataGridBeginningEditEventArgs e)
    {
        if (DataContext is ConnectionMonitorViewModel vm)
        {
            vm.IsEditingCell = true;
        }
    }

    private void OnGridCellEditEnding(object? sender, DataGridCellEditEndingEventArgs e)
    {
        if (DataContext is not ConnectionMonitorViewModel vm)
        {
            return;
        }

        if (e.EditAction == DataGridEditAction.Commit
            && e.Row.Item is ConnectionRowViewModel row
            && e.EditingElement is TextBox editor)
        {
            row.SetNoteSilent(editor.Text);
            vm.CommitInlineNote(row);
        }

        Dispatcher.BeginInvoke(vm.NotifyEditingEnded);
    }

    private void OnAutoScrollRequested(object? sender, ConnectionRowViewModel row) =>
        ConnectionsGrid.ScrollIntoView(row);

    private void OnEditNoteRequested(object? sender, ConnectionRowViewModel row)
    {
        ConnectionsGrid.SelectedItem = row;
        ConnectionsGrid.ScrollIntoView(row, NoteColumn);
        ConnectionsGrid.CurrentCell = new DataGridCellInfo(row, NoteColumn);
        ConnectionsGrid.BeginEdit();
    }
}
