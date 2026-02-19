import { Component, input, output, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Vehicle } from '../../model/vehicle';
import { DialogModule } from 'primeng/dialog';
import { TabsModule } from 'primeng/tabs';
import { ButtonModule } from 'primeng/button';
import { PanelModule } from 'primeng/panel';
import { TableModule } from 'primeng/table';
import { OperationUi } from '../operation-ui/operation-ui';
import { SelectModule } from 'primeng/select';
import { CheckboxModule } from 'primeng/checkbox';

@Component({
  selector: 'config-dialog',
  imports: [DialogModule, TabsModule, ButtonModule, PanelModule, TableModule, OperationUi, SelectModule, FormsModule, CheckboxModule],
  templateUrl: './config-dialog.html',
  styleUrl: './config-dialog.css',
})
export class ConfigDialog {
  vehicle = input<Vehicle | null>(null)
  vehicleChange = output<Vehicle | null>()
  continuousInputs = signal([{
    'name': 'speed',
    'type': 'uint8',
    'description': 'Target speed of the robot',
  }, {
    'name': 'angle',
    'type': 'uint8',
    'description': 'Target angle of the robot',
  }])
  continuousOutputs = signal([{
    'name': 'speed',
    'type': 'uint8',
    'description': 'Current speed of the robot',
  }, {
    'name': 'angle',
    'type': 'uint8',
    'description': 'Current angle of the robot',
  }, {
    'name': 'front',
    'type': 'video',
    'description': 'Video stream of front camera',
  }])
  commands = signal([{
    'name': 'stop',
    'parameters': 0,
    'description': 'Emergency stop',
  }, {
    'name': 'open',
    'parameters': 0,
    'description': 'Open cargo box',
  }])
  keyboardEnabled = signal(true)
  keyboardModes = [
    { 'name': 'Increase', 'value': 'inc' },
    { 'name': 'Decrease', 'value': 'dec' },
    { 'name': 'Set', 'value': 'set' },
    { 'name': 'Reset', 'value': 'reset' },
  ]
  keyboardBindings = signal([
    {
      'key': 'w',
      'param': 'speed',
      'mode': 'inc',
    },
    {
      'key': 's',
      'param': 'speed',
      'mode': 'dec',
    },
    {
      'key': 'a',
      'param': 'angle',
      'mode': 'inc',
    },
    {
      'key': 'd',
      'param': 'speed',
      'mode': 'dec',
    },
    {
      'key': 'space',
      'param': 'speed',
      'mode': 'reset',
    },
  ])
  smartphoneEnabled = signal(false)
  smartphoneMoves = signal([
    {
      'name': 'Rotate',
      'value': 'rotate',
    },
    {
      'name': 'Tilt',
      'value': 'tilt'
    }
  ])
  smartphoneBindings = signal([
    {
      'move': 'rotate',
      'param': 'angle',
    },
    {
      'move': 'tilt',
      'param': 'speed',
    }
  ])
  gamepadEnabled = signal(true)
  gamepadBindings = signal([
    {
      'type': 'axes',
      'index': 0,
      'param': 'angle',
    },
    {
      'type': 'button',
      'index': 0,
      'param': 'speed'
    }
  ])
}
