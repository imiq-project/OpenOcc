import { Component, ViewChild } from '@angular/core';
import { DrawerModule } from 'primeng/drawer';
import { ButtonModule } from 'primeng/button';
import { AvatarModule } from 'primeng/avatar';

@Component({
    selector: 'drawer',
    templateUrl: './drawer.html',
    standalone: true,
    imports: [DrawerModule, ButtonModule, AvatarModule]
})
export class AppDrawer {
    visible: boolean = false;
    closeCallback(): void {
      this.visible = true;
    }
}