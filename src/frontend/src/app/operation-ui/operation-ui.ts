import { Component, input, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { KnobModule } from 'primeng/knob';
import { SliderModule } from 'primeng/slider';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'operation-ui',
  imports: [CommonModule, KnobModule, SliderModule, FormsModule],
  templateUrl: './operation-ui.html',
  styleUrl: './operation-ui.css',
})
export class OperationUi {
  editable = input<boolean>(false)
  configuration = signal([
    {
      'type': 'video',
      'param': 'video',
      'top': 5,
      'left': 5,
      'width': 95,
      'height': 80,
    },
    {
      'type': 'knob',
      'param': 'angle',
      'top': 75,
      'left': 40,
      'width': 100,
      'height': 100,
    },
    {
      'type': 'slider',
      'param': 'speed',
      'top': 85,
      'left': 60,
      'width': 30,
      'height': 10,
    }
  ])

  styleFor(item: any, includeWidth: boolean = true) {
    // TODO: does not work for p-knob
    return {
      left: item.left + '%',
      top: item.top + '%',
      width: includeWidth ? item.width + '%' : 'unset',
      height: includeWidth ?  item.height + '%' : 'unset',
      position: 'absolute',
    }
  }
}
