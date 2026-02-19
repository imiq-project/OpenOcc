import { Component, input, output } from '@angular/core';
import { DrawerModule } from 'primeng/drawer';
import { ButtonModule } from 'primeng/button';
import { AvatarModule } from 'primeng/avatar';
import { PanelModule } from 'primeng/panel';
import { Vehicle } from '../../model/vehicle';
import { TagModule } from 'primeng/tag';

@Component({
    selector: 'drawer',
    templateUrl: './drawer.html',
    standalone: true,
    imports: [DrawerModule, ButtonModule, AvatarModule, PanelModule, TagModule]
})
export class AppDrawer {
    visible: boolean = false;
    vehicles = input<Vehicle[]>([])
    configureVehicle = output<Vehicle>()

    onClose(): void {
        this.visible = true;
    }

    onConfigureVehicle(vehicle: Vehicle): void {
        this.configureVehicle.emit(vehicle)
    }
}